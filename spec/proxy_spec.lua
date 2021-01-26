local http_ng_response = require('resty.http_ng.response')
local lrucache = require('resty.lrucache')

local configuration_store = require 'apicast.configuration_store'
local Service = require 'apicast.configuration.service'
local Usage = require 'apicast.usage'
local test_backend_client = require 'resty.http_ng.backend.test'
local errors = require 'apicast.errors'

describe('Proxy', function()
  local configuration, proxy, test_backend

  before_each(function()
    configuration = configuration_store.new()
    proxy = require('apicast.proxy').new(configuration)
    test_backend = test_backend_client.new()
    proxy.http_ng_backend = test_backend
  end)

  it('has access function', function()
    assert.truthy(proxy.access)
    assert.same('function', type(proxy.access))
  end)

  describe(':rewrite', function()
    local service
    before_each(function()
      -- Replace original ngx.header. Openresty does not allow to modify it when
      -- running busted tests.
      ngx.header = {}

      ngx.var = { backend_endpoint = 'http://localhost:1853', uri = '/a/uri' }
      stub(ngx.req, 'get_method', function () return 'GET' end)
      service = Service.new({ extract_usage = function() end })
    end)

    it('works with part of the credentials', function()
      service.credentials = { location = 'headers' }
      service.backend_version = 2
      ngx.var.http_app_key = 'key'
      local context = {}
      assert.falsy(proxy:rewrite(service, context))
    end)
  end)

  it('has post_action function', function()
    assert.truthy(proxy.post_action)
    assert.same('function', type(proxy.post_action))
  end)

  describe('.get_upstream', function()
    local get_upstream
    before_each(function() get_upstream = proxy.get_upstream end)

    it('sets correct upstream port', function()
      assert.same(443, get_upstream({ api_backend = 'https://example.com' }):port())
      assert.same(80, get_upstream({ api_backend = 'http://example.com' }):port())
      assert.same(8080, get_upstream({ api_backend = 'http://example.com:8080' }):port())
    end)
  end)

  describe('.authorize', function()
    local service = { backend_authentication = { value = 'not_baz' }, backend = { endpoint = 'http://0.0.0.0' } }

    local context

    before_each(function()
      context = {
        cache_handler = function() end,
        publish_backend_auth = function() end
      }
    end)

    it('takes ttl value if sent', function()
      local ttl = 80
      ngx.var = { cached_key = 'client_id=blah', http_x_3scale_debug='baz', real_url='blah' }

      local response = { status = 200 }
      stub(test_backend, 'send', function() return response end)

      stub(proxy, 'cache_handler').returns(true)

      local usage = Usage.new()
      usage:add('foo', 0)
      proxy:authorize(context, service, usage, { client_id = 'blah' }, ttl)

      assert.spy(proxy.cache_handler).was.called_with(
        proxy.cache, 'client_id=blah:usage%5Bfoo%5D=0', response, ttl)
    end)

    it('works with no ttl', function()
      ngx.var = { cached_key = "client_id=blah", http_x_3scale_debug='baz', real_url='blah' }

      local response = { status = 200 }
      stub(test_backend, 'send', function() return response end)
      stub(proxy, 'cache_handler').returns(true)

      local usage = Usage.new()
      usage:add('foo', 0)
      proxy:authorize(context, service, usage, { client_id = 'blah' })

      assert.spy(proxy.cache_handler).was.called_with(
        proxy.cache, 'client_id=blah:usage%5Bfoo%5D=0', response, nil)
    end)

    it('does not use cached auth if creds are the same but extra authrep params are not', function()
      proxy.extra_params_backend_authrep = { referrer = '3scale.net' }

      stub(test_backend, 'send', function() return { status = 200 } end)

      local usage = Usage.new()
      usage:add('hits', 1)
      local cache_key = "uk:usage%5Bhits%5D=1" -- Referrer not here
      proxy.cache:set(cache_key, 200)
      ngx.var = { cached_key = "uk" } -- authorize() expects creds to be set up

      proxy:authorize(context, service, usage, { user_key = 'uk' })

      -- Calls backend because the call is not cached
      assert.stub(test_backend.send).was_called()
    end)

    it('uses cached auth if creds are the same and authrep params too', function()
      proxy.extra_params_backend_authrep = { referrer = '3scale.net' }

      stub(test_backend, 'send', function() return { status = 200 } end)

      local usage = Usage.new()
      usage:add('hits', 1)
      local cache_key = "uk:usage%5Bhits%5D=1:referrer=3scale.net" -- Referrer here
      proxy.cache:set(cache_key, 200)
      ngx.var = { cached_key = "uk" } -- authorize() expects creds to be set up

      proxy:authorize(context, service, usage, { user_key = 'uk' })

      -- Does not call backend because the call is cached
      assert.stub(test_backend.send).was_not_called()
    end)

    it('returns "limits exceeded" with the "Retry-After" given by the 3scale backend', function()
      ngx.header = {}
      ngx.var = { cached_key = "uk" } -- authorize() expects creds to be set up
      stub(errors, 'limits_exceeded')
      local retry_after = 60
      local usage = Usage.new()
      usage:add('hits', 1)

      test_backend.expect({}).respond_with(
        {
          status = 409,
          headers = {
            ['3scale-limit-reset'] = retry_after,
            ['3scale-rejection-reason'] = 'limits_exceeded'
          }
        }
      )

      proxy:authorize(context, service, usage, { user_key = 'uk' })

      assert.stub(errors.limits_exceeded).was_called_with(service, retry_after)
    end)
  end)

  describe('.handle_backend_response', function()

    local context

    before_each(function()
      context = {
        cache_handler = function() end,
        publish_backend_auth = function() end
      }
    end)

    it('returns a rejection reason when given', function()
      local authorized, rejection_reason = proxy:handle_backend_response(
        context,
        lrucache.new(1),
        http_ng_response.new(nil, 403, { ['3scale-rejection-reason'] = 'some_reason' }, ''),
        nil)

      assert.falsy(authorized)
      assert.equal('some_reason', rejection_reason)
    end)

    it('returns an empty rejection reason instead of "limits exceeded" for disabled metrics', function()
      local authorized, rejection_reason = proxy:handle_backend_response(
        context,
        lrucache.new(1),
        http_ng_response.new(
            nil,
            409,
            {
              ['3scale-rejection-reason'] = 'limits_exceeded',
              ['3scale-limit-max-value'] = 0,
            },
            ''
        ),
        nil
      )

      assert.falsy(authorized)
      assert.is_nil(rejection_reason)
    end)

    it('returns limits exceeded for enabled metrics', function()
      local authorized, rejection_reason = proxy:handle_backend_response(
          context,
          lrucache.new(1),
          http_ng_response.new(
              nil,
              409,
              {
                ['3scale-rejection-reason'] = 'limits_exceeded',
                ['3scale-limit-max-value'] = 100,
              },
              ''
          ),
          nil
      )

      assert.falsy(authorized)
      assert.equal('limits_exceeded', rejection_reason)
    end)

    describe('when backend is unavailable', function()
      local backend_unavailable_statuses = { 0, 499, 502 } -- Not exhaustive
      local cache_key = 'a_cache_key'

      before_each(function()
        -- So we can set the value for the cached auth ensuring that the
        -- handler will not modify it.
        proxy.cache_handler = function() end
      end)

      it('returns true when the cached authorization is authorized', function()
        proxy.cache:set(cache_key, 200)

        for _, status in ipairs(backend_unavailable_statuses) do
          local authorized = proxy:handle_backend_response(context, cache_key, { status = status })
          assert(authorized)
        end
      end)

      it('returns false when the authorization is not cached', function()
        proxy.cache:delete(cache_key)

        for _, status in ipairs(backend_unavailable_statuses) do
          local authorized = proxy:handle_backend_response(context, cache_key, { status = status })
          assert.falsy(authorized)
        end
      end)

      it('returns false when the authorization is cached and denied', function()
        proxy.cache:set(cache_key, 429)

        for _, status in ipairs(backend_unavailable_statuses) do
          local authorized = proxy:handle_backend_response(context, cache_key, { status = status })
          assert.falsy(authorized)
        end
      end)
    end)
  end)
end)
