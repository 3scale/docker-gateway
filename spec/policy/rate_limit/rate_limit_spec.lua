local RateLimitPolicy = require('apicast.policy.rate_limit')
local ngx_variable = require('apicast.policy.ngx_variable')
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

local redis_host = env.get('TEST_NGINX_REDIS_HOST') or '127.0.0.1'
local redis_port = env.get('TEST_NGINX_REDIS_PORT') or 6379

local redis_url = 'redis://'..redis_host..':'..redis_port..'/1'
local redis = ts.connect_redis{ url = redis_url }

describe('Rate limit policy', function()
  local context

  before_each(function()
    redis:flushdb()

    stub(ngx, 'exit')
    stub(ngx, 'sleep')

    stub(ngx, 'time', function() return 11111 end)

    -- By default expose the context shared by the policies.
    stub(ngx_variable, 'available_context', function(policies_context)
      return policies_context
    end)
  end)

  before_each(function()
    ngx.var = { request_time = '0.060', }

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
            { key = { name = 'test1', scope = 'global' }, conn = 1, burst = 0, delay = 0.5 }
          },
          leaky_bucket_limiters = {
            { key = { name = 'test2', scope = 'global' }, rate = 1, burst = 0 }
          },
          fixed_window_limiters = {
            { key = { name = 'test3', scope = 'global' }, count = 1, window = 1 }
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
            { key = { name = 'test1', scope = 'global' }, conn = 20, burst = 10, delay = 0.4 }
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

        assert.returns_error('failed to connect to redis on invalidhost:6379: invalidhost could not be resolved (3: Host not found)', rate_limit_policy:access(context))

        assert.spy(ngx.exit).was_called_with(500)
      end)

      it('redis url is empty', function()
        local rate_limit_policy = RateLimitPolicy.new({
          connection_limiters = {
            { key = { name = 'test1', scope = 'global' }, conn = 20, burst = 10, delay = 0.5 }
          },
          redis_url = ''
        })

        assert(rate_limit_policy:access(context))
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

          assert.spy(ngx.exit).was_called_with(429)
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

          assert.spy(ngx.exit).was_called_with(429)
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

          assert.equal('1', redis:get('11110_fixed_window_test3'))
          assert.spy(ngx.exit).was_called_with(429)
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

          assert.equal('1', redis:get('11110_fixed_window_test3'))
          assert.spy(ngx.exit).was_called_with(429)
        end)

        it('rejected (count), name_type is liquid and refers to var in the context', function()
          local test_host = 'some_host'
          ngx_variable.available_context:revert()
          stub(ngx_variable, 'available_context', function()
            return { host = test_host }
          end)

          local rate_limit_policy = RateLimitPolicy.new({
            fixed_window_limiters = {
              { key = { name = '{{ host }}', name_type = 'liquid', scope = 'global' }, count = 1, window = 10 }
            },
            redis_url = redis_url
          })

          assert(rate_limit_policy:access(context))
          assert.returns_error('limits exceeded', rate_limit_policy:access(context))

          assert.equal('1', redis:get('11110_fixed_window_' .. test_host))
          assert.spy(ngx.exit).was_called_with(429)
        end)

        it('rejected (count), multi limiters', function()
          local ctx = {
            service = { id = 5 }, var1 = 'test3_1', var2 = 'test3_2', var3 = 'test3_3' }
          local rate_limit_policy = RateLimitPolicy.new({
            fixed_window_limiters = {
              { key = { name = '{{ var1 }}', name_type = 'liquid' }, count = 1, window = 10 },
              { key = { name = '{{ var2 }}', name_type = 'liquid' }, count = 2, window = 10 },
              { key = { name = '{{ var3 }}', name_type = 'liquid' }, count = 3, window = 10 }
            },
            redis_url = redis_url
          })

          assert(rate_limit_policy:access(ctx))
          assert.returns_error('limits exceeded', rate_limit_policy:access(ctx))

          assert.equal('1', redis:get('11110_5_fixed_window_test3_1'))
          assert.equal('1', redis:get('11110_5_fixed_window_test3_2'))
          assert.equal('1', redis:get('11110_5_fixed_window_test3_3'))
          assert.spy(ngx.exit).was_called_with(429)
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

          assert.spy(ngx.sleep).was_called_with(match.is_gt(0.000))
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

          assert.spy(ngx.sleep).was_called_with(match.is_gt(0.000))
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

          assert.spy(ngx.sleep).was_called_with(match.is_gt(0.001))
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

          assert.spy(ngx.sleep).was_called_with(match.is_gt(0.001))
        end)
      end)
    end)

    describe('when conditions are defined', function()
      local true_condition = {
        operations = {
          { left = '1', op = '==', right = '1' }
        }
      }

      local false_condition = {
        operations = {
          { left = '1', op = '==', right = '2' }
        }
      }

      describe('and the type of the limit is "connection"', function()
        it('applies the limit when the condition is true', function()
          local rate_limit_policy = RateLimitPolicy.new({
            connection_limiters = {
              {
                key = { name = 'limit_key', name_type = 'plain', scope = 'global' },
                conn = 1, burst = 0, delay = 0.5,
                condition = true_condition
              }
            }
          })

          assert(rate_limit_policy:access(context))

          assert.returns_error('limits exceeded', rate_limit_policy:access(context))
          assert.spy(ngx.exit).was_called_with(429)
        end)

        it('does not apply the limit when the condition is false', function()
          local rate_limit_policy = RateLimitPolicy.new({
            connection_limiters = {
              {
                key = { name = 'limit_key', name_type = 'plain', scope = 'global' },
                conn = 1, burst = 0, delay = 0.5,
                condition = false_condition
              }
            }
          })

          -- Limit is 1. Make 2 requests and check that they're not limited
          assert(rate_limit_policy:access(context))
          assert(rate_limit_policy:access(context))
        end)
      end)

      describe('and the type of the limit is "leaky_bucket"', function()
        it('applies the limit when the condition is true', function()
          local rate_limit_policy = RateLimitPolicy.new({
            leaky_bucket_limiters = {
              {
                key = { name = 'limit_key', name_type = 'plain', scope = 'global' },
                rate = 1,
                burst = 0,
                condition = true_condition
              }
            }
          })

          assert(rate_limit_policy:access(context))

          assert.returns_error('limits exceeded', rate_limit_policy:access(context))
          assert.spy(ngx.exit).was_called_with(429)
        end)

        it('does not apply the limit when the condition is false', function()
          local rate_limit_policy = RateLimitPolicy.new({
            leaky_bucket_limiters = {
              {
                key = { name = 'limit_key', name_type = 'plain', scope = 'global' },
                rate = 1,
                burst = 0,
                condition = false_condition
              }
            }
          })

          -- Limit is 1. Make 2 requests and check that they're not limited
          assert(rate_limit_policy:access(context))
          assert(rate_limit_policy:access(context))
        end)
      end)

      describe('and the type of the limits is "fixed_window"', function()
        it('applies the limit when the condition is true', function()
          local rate_limit_policy = RateLimitPolicy.new({
            fixed_window_limiters = {
              {
                key = { name = 'limit_key', name_type = 'plain', scope = 'global' },
                count = 1,
                window = 10,
                condition = true_condition
              }
            }
          })

          assert(rate_limit_policy:access(context))

          assert.returns_error('limits exceeded', rate_limit_policy:access(context))
          assert.spy(ngx.exit).was_called_with(429)
        end)

        it('does not apply the limit when the condition is false', function()
          local rate_limit_policy = RateLimitPolicy.new({
            fixed_window_limiters = {
              {
                key = { name = 'limit_key', name_type = 'plain', scope = 'global' },
                count = 1,
                window = 10,
                condition = false_condition
              }
            }
          })

          -- Limit is 1. Make 2 requests and check that they're not limited
          assert(rate_limit_policy:access(context))
          assert(rate_limit_policy:access(context))
        end)
      end)

      describe('and there are several limits applied', function()
        it('denies access when the condition of any limit is false', function()
          local rate_limit_policy = RateLimitPolicy.new({
            leaky_bucket_limiters = {
              {
                key = { name = 'limit_key', name_type = 'plain', scope = 'global' },
                rate = 1,
                burst = 0,
                condition = false_condition
              }
            },
            fixed_window_limiters = {
              {
                key = { name = 'limit_key', name_type = 'plain', scope = 'global' },
                count = 1,
                window = 10,
                condition = true_condition
              }
            },
            connection_limiters = {
              {
                key = { name = 'limit_key', name_type = 'plain', scope = 'global' },
                conn = 1, burst = 0, delay = 0.5,
                condition = true_condition
              }
            }
          })

          assert(rate_limit_policy:access(context))

          assert.returns_error('limits exceeded', rate_limit_policy:access(context))
          assert.spy(ngx.exit).was_called_with(429)
        end)
      end)
    end)

    it('accepts "matches" as an operation in the conditions', function()
      local condition_with_matches = {
        operations = {
          {
            left = '{{ uri }}',
            left_type = 'liquid',
            op = 'matches',
            right = '/v1/.*/something/.*',
            right_type = 'plain'
          }
        }
      }

      local rate_limit_policy = RateLimitPolicy.new({
        fixed_window_limiters = {
          {
            key = { name = 'limit_key', name_type = 'plain', scope = 'global' },
            count = 2,
            window = 10,
            condition = condition_with_matches
          }
        }
      })

      -- We are going to make 3 requests that match the url pattern defined
      -- above. As the limit is set to 2, only the third one should fail.

      ngx_variable.available_context:revert()
      stub(ngx_variable, 'available_context', function()
        return { uri = '/v1/aaa/something/bbb' }
      end)
      assert(rate_limit_policy:access({}))

      ngx_variable.available_context:revert()
      stub(ngx_variable, 'available_context', function()
        return { uri = '/v1/ccc/something/ddd' }
      end)
      assert(rate_limit_policy:access({}))

      ngx_variable.available_context:revert()
      stub(ngx_variable, 'available_context', function()
        return { uri = '/v1/eee/something/fff' }
      end)
      assert.returns_error('limits exceeded', rate_limit_policy:access({}))
      assert.spy(ngx.exit).was_called_with(429)
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

    it('success when redis url is empty', function()
      local rate_limit_policy = RateLimitPolicy.new({
        connection_limiters = {
          { key = { name = 'test1', scope = 'global' }, conn = 20, burst = 10, delay = 0.5 }
        },
        redis_url = ''
      })

      assert(rate_limit_policy:access(context))

      assert(rate_limit_policy:log())
    end)
  end)
end)
