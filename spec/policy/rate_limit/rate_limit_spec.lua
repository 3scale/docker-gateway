local RateLimitPolicy = require('apicast.policy.rate_limit')
local match = require('luassert.match')
local env = require('resty.env')
local function init_val()
  ngx.var = {}
  ngx.var.request_time = '0.060'

  ngx.shared.limiter = {}
  ngx.shared.limiter.get = function(_, key)
    return ngx.shared.limiter[key]
  end
  ngx.shared.limiter.set = function(_, key, val)
    ngx.shared.limiter[key] = val
  end
  ngx.shared.limiter.incr = function(_, key, val, init)
    local v = ngx.shared.limiter[key]
    if not v then
      ngx.shared.limiter[key] = val + init
    else
      ngx.shared.limiter[key] = v + val
    end
    return ngx.shared.limiter[key]
  end
  ngx.shared.limiter.expire = function(_, _, _)
    return true, nil
  end
end

local function is_gt(_, arguments)
  local expected = arguments[1]
  return function(value)
    return value > expected
  end
end
assert:register("matcher", "gt", is_gt)

local redis_host = env.get('TEST_NGINX_REDIS_HOST') or 'localhost'
local redis_port = env.get('TEST_NGINX_REDIS_PORT') or 6379

describe('Rate limit policy', function()
  local ngx_exit_spy
  local ngx_sleep_spy

  setup(function()
    ngx_exit_spy = spy.on(ngx, 'exit')
    ngx_sleep_spy = spy.on(ngx, 'sleep')
  end)

  before_each(function()
    local redis = require('resty.redis'):new()
    redis:connect(redis_host, redis_port)
    redis:select(1)
    redis:del('connections_test1', 'leaky_bucket_test2', 'fixed_window_test3', 'bank_A_leaky_bucket_test4')
    init_val()
  end)

  describe('.access', function()
    it('success with multiple limiters', function()
      local config = {
        connection_limiters = {
          { key = { name = 'test1' }, conn = 20, burst = 10, delay = 0.5 }
        },
        leaky_bucket_limiters = {
          { key = { name = 'test2' }, rate = 18, burst = 9 }
        },
        fixed_window_limiters = {
          { key = {name = 'test3'}, count = 10, window = 10 }
        },
        redis_url = 'redis://'..redis_host..':'..redis_port..'/1'
      }
      local rate_limit_policy = RateLimitPolicy.new(config)
      rate_limit_policy:access()
    end)

    it('no redis url', function()
      local config = {
        connection_limiters = {
          { key = { name = 'test1' }, conn = 20, burst = 10, delay = 0.5 }
        },
        leaky_bucket_limiters = {
          { key = { name = 'test2' }, rate = 18, burst = 9 }
        },
        fixed_window_limiters = {
          { key = { name = 'test3' }, count = 10, window = 10 }
        }
      }
      local rate_limit_policy = RateLimitPolicy.new(config)
      rate_limit_policy:access()
    end)

    it('invalid redis url', function()
      local config = {
        connection_limiters = {
          { key = { name = 'test1' }, conn = 20, burst = 10, delay = 0.5 }
        },
        redis_url = 'redis://invalidhost:'..redis_port..'/1'
      }
      local rate_limit_policy = RateLimitPolicy.new(config)
      rate_limit_policy:access()
      assert.spy(ngx_exit_spy).was_called_with(500)
    end)

    it('rejected (conn)', function()
      local config = {
        connection_limiters = {
          { key = { name = 'test1' }, conn = 1, burst = 0, delay = 0.5 }
        },
        redis_url = 'redis://'..redis_host..':'..redis_port..'/1'
      }
      local rate_limit_policy = RateLimitPolicy.new(config)
      rate_limit_policy:access()
      rate_limit_policy:access()
      assert.spy(ngx_exit_spy).was_called_with(429)
    end)

    it('rejected (req)', function()
      local config = {
        leaky_bucket_limiters = {
          { key = { name = 'test2' }, rate = 1, burst = 0 }
        },
        redis_url = 'redis://'..redis_host..':'..redis_port..'/1'
      }
      local rate_limit_policy = RateLimitPolicy.new(config)
      rate_limit_policy:access()
      rate_limit_policy:access()
      assert.spy(ngx_exit_spy).was_called_with(429)
    end)

    it('rejected (count)', function()
      local config = {
        fixed_window_limiters = {
          { key = { name = 'test3' }, count = 1, window = 10 }
        },
        redis_url = 'redis://'..redis_host..':'..redis_port..'/1'
      }
      local rate_limit_policy = RateLimitPolicy.new(config)
      rate_limit_policy:access()
      rate_limit_policy:access()
      assert.spy(ngx_exit_spy).was_called_with(429)
    end)

    it('delay (conn)', function()
      local config = {
        connection_limiters = {
          { key = {name = 'test1'}, conn = 1, burst = 1, delay = 2 }
        },
        redis_url = 'redis://'..redis_host..':'..redis_port..'/1'
      }
      local rate_limit_policy = RateLimitPolicy.new(config)
      rate_limit_policy:access()
      rate_limit_policy:access()
      assert.spy(ngx_sleep_spy).was_called_with(match.is_gt(0.001))
    end)

    it('delay (req)', function()
      local config = {
        leaky_bucket_limiters = {
          { key = { name = 'test2', scope = 'global' }, rate = 1, burst = 1 }
        },
        redis_url = 'redis://'..redis_host..':'..redis_port..'/1'
      }
      local rate_limit_policy = RateLimitPolicy.new(config)
      rate_limit_policy:access()
      rate_limit_policy:access()
      assert.spy(ngx_sleep_spy).was_called_with(match.is_gt(0.001))
    end)

    it('delay (req) service scope', function()
      local config = {
        leaky_bucket_limiters = {
          {
            key = { name = 'test4', scope = 'service', service_name = 'bank_A' },
            rate = 1,
            burst = 1
          }
        },
        redis_url = 'redis://'..redis_host..':'..redis_port..'/1'
      }
      local rate_limit_policy = RateLimitPolicy.new(config)
      rate_limit_policy:access()
      rate_limit_policy:access()
      assert.spy(ngx_sleep_spy).was_called_with(match.is_gt(0.001))
    end)
  end)

  describe('.log', function()
    it('success in leaving', function()
      local config = {
        connection_limiters = {
          { key = {name = 'test1'}, conn = 20, burst = 10, delay = 0.5 }
        },
        redis_url = 'redis://'..redis_host..':'..redis_port..'/1'
      }
      local rate_limit_policy = RateLimitPolicy.new(config)
      rate_limit_policy:access()
      rate_limit_policy:log()
    end)
  end)
end)
