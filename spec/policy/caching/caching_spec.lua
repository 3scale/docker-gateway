local resty_lrucache = require('resty.lrucache')

describe('Caching policy', function()
  local cache
  local caching_policy
  local cache_handler

  before_each(function()
    cache = resty_lrucache.new(1)

    -- The code uses ngx.shared.dict and it defines .add(), resty_lrucache
    -- does not, so we need to implement it for these tests.
    cache.add = function(self, key, value)
      if not self:get(key) then
        return self:set(key, value)
      end
    end
  end)

  describe('.export', function()
    describe('when configured as strict', function()
      before_each(function()
        local config = { caching_type = 'strict' }
        caching_policy = require('apicast.policy.caching').new(config)
        cache_handler = caching_policy:export().cache_handler
      end)

      it('caches authorized requests', function()
        cache_handler(cache, 'a_key', { status = 200 }, nil)
        assert.equals(200, cache:get('a_key'))
      end)

      it('clears the cache entry for a request when it is denied', function()
        cache:set('a_key', 200)

        cache_handler(cache, 'a_key', { status = 403 }, nil)
        assert.is_nil(cache:get('a_key'))
      end)

      it('clears the cache entry for a request when it fails', function()
        cache:set('a_key', 200)

        cache_handler(cache, 'a_key', { status = 500 }, nil)
        assert.is_nil(cache:get('a_key'))
      end)
    end)

    describe('when configured as resilient', function()
      before_each(function()
        local config = { caching_type = 'resilient' }
        caching_policy = require('apicast.policy.caching').new(config)
        cache_handler = caching_policy:export().cache_handler
      end)

      it('caches authorized requests', function()
        cache_handler(cache, 'a_key', { status = 200 }, nil)
        assert.equals(200, cache:get('a_key'))
      end)

      it('caches denied requests', function()
        cache_handler(cache, 'a_key', { status = 403 }, nil)
        assert.equals(403, cache:get('a_key'))
      end)

      it('does not clear the cache entry for a request when it fails', function()
        cache:set('a_key', 200)

        cache_handler(cache, 'a_key', { status = 500 }, nil)
        assert.equals(200, cache:get('a_key'))
      end)

      it('does not cached connect issues', function()
        cache_handler(cache, 'a_key', { status = 0 }, nil)
        assert.equals(nil, cache:get('a_key'))
      end)
    end)

    describe('when configured as allow', function()
      before_each(function()
        local config = { caching_type = 'allow' }
        caching_policy = require('apicast.policy.caching').new(config)
        cache_handler = caching_policy:export().cache_handler
      end)

      it('caches authorized requests', function()
        cache_handler(cache, 'a_key', { status = 200 }, nil)
        assert.equals(200, cache:get('a_key'))
      end)

      it('caches denied requests', function()
        cache_handler(cache, 'a_key', { status = 403 }, nil)
        assert.equals(403, cache:get('a_key'))
      end)

      it('does not cached connect issues', function()
        cache_handler(cache, 'a_key', { status = 0 }, nil)
        assert.equals(200, cache:get('a_key'))
      end)

      describe('and backend returns 5XX', function()
        it('does not invalidate the cache entry if there was a 4XX', function()
          cache:set('a_key', 403)
          cache_handler(cache, 'a_key', { status = 500 }, nil)
          assert.equals(403, cache:get('a_key'))
        end)

        it('caches a 200 if there was nothing in the cache entry', function()
          cache_handler(cache, 'a_key', { status = 500 }, nil)
          assert.equals(200, cache:get('a_key'))
        end)

        it('caches a 200 if there was something != 4XX in the cache entry', function()
          cache:set('a_key', 200)
          cache_handler(cache, 'a_key', { status = 500 }, nil)
          assert.equals(200, cache:get('a_key'))
        end)
      end)
    end)

    describe('when disabled', function()
      setup(function()
        local config = { caching_type = 'none' }
        caching_policy = require('apicast.policy.caching').new(config)
        cache_handler = caching_policy:export().cache_handler
      end)

      it('does not cache anything', function()
        cache_handler(cache, 'a_key', { status = 200 }, nil)
        assert.is_nil(cache:get('a_key'))
      end)

      it("clears the cache if it's present", function()
          -- THREESCALE-4464
          cache:set('a_key', 200)

          cache_handler(cache, 'a_key', { status = 200 }, nil)
          assert.is_nil(cache:get('a_key'))
      end)

    end)
  end)
end)
