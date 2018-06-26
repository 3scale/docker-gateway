local RateLimitPolicy = require('apicast.policy.rate_limit')
local match = require('luassert.match')
local env = require('resty.env')

local shdict_mt = {
  __index = {
    get = function(t, k) return rawget(t, k) end,
    set = function(t, k, v) rawset(t, k , v); return true end,
    incr = function(t, key, inc, init, _)
      local value = t:get(key) or init
      if not value then return nil, 'not found' end

      t:set(key, value + inc)
      return t:get(key)
    end,
  }
}
local function shdict()
  return setmetatable({ }, shdict_mt)
end

local ts = require ('apicast.threescale_utils')

local redis_host = env.get('TEST_NGINX_REDIS_HOST') or 'localhost'
local redis_port = env.get('TEST_NGINX_REDIS_PORT') or 6379

local redis_url = 'redis://'..redis_host..':'..redis_port..'/1'
local redis = ts.connect_redis{ url = redis_url }

describe('Rate limit policy', function()
  local ngx_exit
  local ngx_sleep
  local context

  setup(function()
    ngx_exit = stub(ngx, 'exit')
    ngx_sleep = stub(ngx, 'sleep')

    stub(ngx, 'time', function() return 11111 end)
    stub(ngx.req, 'get_method', function() return 'GET' end)
  end)

  before_each(function()
    redis:flushdb()
  end)

  before_each(function()
    ngx.var = {
      request_time = '0.060',
      host = 'test3',
    }

    ngx.shared.limiter = mock(shdict(), true)

    context = {
      service = {
        id = 5
      }
    }
  end)

  describe('.access', function()
    describe('missing shdict', function ()
      before_each(function()
        ngx.shared.limiter = nil
      end)

      it('does not crash', function()
        local rate_limit_policy = RateLimitPolicy.new({
          connection_limiters = {
            { key = { name = 'test1', scope = 'global' }, conn = 0, burst = 0, delay = 0 }
          },
          leaky_bucket_limiters = {
            { key = { name = 'test2', scope = 'global' }, rate = 0, burst = 0 }
          },
          fixed_window_limiters = {
            { key = { name = 'test3', scope = 'global' }, count = 0, window = 0 }
          },
        })

        assert(rate_limit_policy:access(context))
      end)
    end)

    describe('using #shmem', function()
      before_each(function()
        ngx.shared.limiter = shdict()
      end)

      it('works without redis', function()
        local rate_limit_policy = RateLimitPolicy.new({
          connection_limiters = {
            { key = { name = 'test1', scope = 'global' }, conn = 20, burst = 10, delay = 0.5 }
          }
        })

        assert(rate_limit_policy:access(context))
      end)

      it('works with multiple limiters', function()
        local rate_limit_policy = RateLimitPolicy.new({
          connection_limiters = {
            { key = { name = 'test1', scope = 'global' }, conn = 20, burst = 10, delay = 0.5 }
          },
          leaky_bucket_limiters = {
            { key = { name = 'test2', scope = 'global' }, rate = 18, burst = 9 }
          },
          fixed_window_limiters = {
            { key = { name = 'test3', scope = 'global' }, count = 10, window = 10 }
          },
        })

        assert(rate_limit_policy:access(context))
      end)
    end)

    describe('using #redis', function()
      it('works with multiple limiters', function()
        local rate_limit_policy = RateLimitPolicy.new({
          connection_limiters = {
            { key = { name = 'test1', scope = 'global' }, conn = 20, burst = 10, delay = 0.5 }
          },
          leaky_bucket_limiters = {
            { key = { name = 'test2', scope = 'global' }, rate = 18, burst = 9 }
          },
          fixed_window_limiters = {
            { key = { name = 'test3', scope = 'global' }, count = 10, window = 10 }
          },
          redis_url = redis_url
        })

        assert(rate_limit_policy:access(context))
      end)

      it('invalid redis url', function()
        local rate_limit_policy = RateLimitPolicy.new({
          connection_limiters = {
            { key = { name = 'test1', scope = 'global' }, conn = 20, burst = 10, delay = 0.5 }
          },
          redis_url = 'redis://invalidhost:'..redis_port..'/1'
        })

        assert.returns_error('failed to connect to redis on invalidhost:6379', rate_limit_policy:access(context))

        assert.spy(ngx_exit).was_called_with(500)
      end)

      describe('rejection', function()
        it('rejected (conn)', function()
          local rate_limit_policy = RateLimitPolicy.new({
            connection_limiters = {
              { key = { name = 'test1', scope = 'global' }, conn = 1, burst = 0, delay = 0.5 }
            },
            redis_url = redis_url
          })

          assert(rate_limit_policy:access(context))
          assert.returns_error('limits exceeded', rate_limit_policy:access(context))

          assert.spy(ngx_exit).was_called_with(429)
        end)

        it('rejected (req)', function()
          local rate_limit_policy = RateLimitPolicy.new({
            leaky_bucket_limiters = {
              { key = { name = 'test2foofoo', scope = 'global' }, rate = 1, burst = 0 }
            },
            redis_url = redis_url
          })

          assert(rate_limit_policy:access(context))
          assert.returns_error('limits exceeded', rate_limit_policy:access(context))

          assert.spy(ngx_exit).was_called_with(429)
        end)

        it('rejected (count), name_type is plain', function()
          local rate_limit_policy = RateLimitPolicy.new({
            fixed_window_limiters = {
              { key = { name = 'test3', name_type = 'plain', scope = 'global' }, count = 1, window = 10 }
            },
            redis_url = redis_url
          })

          assert(rate_limit_policy:access(context))
          assert.returns_error('limits exceeded', rate_limit_policy:access(context))

          assert.equal('2', redis:get('11110_fixed_window_test3'))
          assert.spy(ngx_exit).was_called_with(429)
        end)

        it('rejected (count), name_type is liquid', function()
          local ctx = { service = { id = 5 }, var_in_context = 'test3' }
          local rate_limit_policy = RateLimitPolicy.new({
            fixed_window_limiters = {
              { key = { name = '{{ var_in_context }}', name_type = 'liquid', scope = 'global' },
                count = 1, window = 10 }
            },
            redis_url = redis_url
          })

          assert(rate_limit_policy:access(ctx))
          assert.returns_error('limits exceeded', rate_limit_policy:access(ctx))

          assert.equal('2', redis:get('11110_fixed_window_test3'))
          assert.spy(ngx_exit).was_called_with(429)
        end)

        it('rejected (count), name_type is liquid, ngx variable', function()
          local rate_limit_policy = RateLimitPolicy.new({
            fixed_window_limiters = {
              { key = { name = '{{ host }}', name_type = 'liquid', scope = 'global' }, count = 1, window = 10 }
            },
            redis_url = redis_url
          })

          assert(rate_limit_policy:access(context))
          assert.returns_error('limits exceeded', rate_limit_policy:access(context))

          assert.equal('2', redis:get('11110_fixed_window_test3'))
          assert.spy(ngx_exit).was_called_with(429)
        end)

        it('rejected (count), with conditions', function()
          local rate_limit_policy = RateLimitPolicy.new({
            fixed_window_limiters = {
              {
                key = { name = '{{ host }}',
                name_type = 'liquid',
                scope = 'global',
                conditions = {
                  { operator = 'equals', value = '{{ host }}', value_type = 'liquid' }
                }
              }, count = 1, window = 10 }
            },
            redis_url = redis_url
          })

          assert(rate_limit_policy:access(context))
          assert.returns_error('limits exceeded', rate_limit_policy:access(context))

          assert.equal('2', redis:get('11110_fixed_window_test3_equals_test3'))
          assert.spy(ngx_exit).was_called_with(429)
        end)
      end)

      describe('delay', function()
        it('delay (conn)', function()
          local rate_limit_policy = RateLimitPolicy.new({
            connection_limiters = {
              { key = { name = 'test1', scope = 'global' }, conn = 1, burst = 1, delay = 2 }
            },
            redis_url = redis_url
          })

          assert(rate_limit_policy:access(context))
          assert(rate_limit_policy:access(context))

          assert.spy(ngx_sleep).was_called_with(match.is_gt(0.000))
        end)

        it('delay (req)', function()
          local rate_limit_policy = RateLimitPolicy.new({
            leaky_bucket_limiters = {
              { key = { name = 'test2', scope = 'global' }, rate = 1, burst = 1 }
            },
            redis_url = redis_url
          })

          assert(rate_limit_policy:access(context))
          assert(rate_limit_policy:access(context))

          assert.spy(ngx_sleep).was_called_with(match.is_gt(0.000))
        end)

        it('delay (req) service scope', function()
          local rate_limit_policy = RateLimitPolicy.new({
            leaky_bucket_limiters = {
              {
                key = { name = 'test4', scope = 'service' },
                rate = 1,
                burst = 1
              }
            },
            redis_url = redis_url
          })

          assert(rate_limit_policy:access(context))
          assert(rate_limit_policy:access(context))

          assert.spy(ngx_sleep).was_called_with(match.is_gt(0.001))
        end)

        it('delay (req) default service scope', function()
          local rate_limit_policy = RateLimitPolicy.new({
            leaky_bucket_limiters = {
              {
                key = { name = 'test4' },
                rate = 1,
                burst = 1
              }
            },
            redis_url = redis_url
          })

          assert(rate_limit_policy:access(context))
          assert(rate_limit_policy:access(context))

          assert.spy(ngx_sleep).was_called_with(match.is_gt(0.001))
        end)
      end)
    end)

    describe('.log', function()
      it('success in leaving', function()
        local rate_limit_policy = RateLimitPolicy.new({
          connection_limiters = {
            { key = { name = 'test1', scope = 'global' }, conn = 20, burst = 10, delay = 0.5 }
          },
          redis_url = redis_url
        })

        assert(rate_limit_policy:access(context))

        assert(rate_limit_policy:log())
      end)
    end)
  end)
end)
