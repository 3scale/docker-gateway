local CORSPolicy = require('apicast.policy.cors')

describe('CORS policy', function()
  describe('.rewrite', function()
    local ngx_exit_spy

    describe('when the request is a CORS preflight', function()
      setup(function()
        ngx_exit_spy = spy.on(ngx, 'exit')

        -- Set ngx req and vars to emulate a CORS preflight
        stub(ngx.req, 'get_method', function() return 'OPTIONS' end)

        ngx.var = {
          http_origin = 'localhost',
          http_access_control_request_method = 'GET'
        }
      end)

      it('exits with status code 204', function()
        local cors = CORSPolicy.new()
        cors:rewrite()
        assert.spy(ngx_exit_spy).was_called_with(204)
      end)
    end)

    describe('when the request is not a CORS preflight', function()
      setup(function()
        ngx_exit_spy = spy.on(ngx, 'exit')
        stub(ngx.req, 'get_method', function() return 'GET' end) -- Not preflight
      end)

      it('does not exit', function()
        local cors = CORSPolicy.new()
        cors:rewrite()
        assert.spy(ngx_exit_spy).was_not_called()
      end)
    end)
  end)

  describe('.header_filter', function()
    before_each(function()
      -- Replace original ngx.header. Openresty does not allow to modify it when
      -- running busted tests.
      ngx.header = {}
    end)

    describe('when the policy configuration defines CORS headers', function()
      setup(function()
        ngx.var = { http_origin = 'localhost' }
      end)

      it('sets those headers', function()
        local policy_config = {
          allow_headers = { 'Content-Type' },
          allow_methods = { 'GET', 'POST' },
          allow_origin = '*',
          max_age = 200;
          allow_credentials = true
        }
        local cors = CORSPolicy.new(policy_config)

        cors:header_filter()

        assert.equals(policy_config.allow_headers,
                      ngx.header['Access-Control-Allow-Headers'])
        assert.same(policy_config.allow_methods,
                    ngx.header['Access-Control-Allow-Methods'])
        assert.equals(policy_config.allow_origin,
                      ngx.header['Access-Control-Allow-Origin'])
        assert.equals(policy_config.allow_credentials,
                      ngx.header['Access-Control-Allow-Credentials'])
        assert.equals(policy_config.max_age,
                      ngx.header['Access-Control-Max-Age'])
      end)
    end)

    describe('when the policy configuration does not define CORS headers', function()
      -- Request Data
      local req_http_method = 'GET'
      local req_http_origin = 'localhost'
      local req_http_request_headers = { 'Content-Type', 'Some-Header' }
      local req_http_request_method = { 'GET', 'POST' }

      setup(function()
        stub(ngx.req, 'get_method', function() return req_http_method end)
        ngx.var = {
          http_origin = req_http_origin,
          http_access_control_request_headers = req_http_request_headers,
          http_access_control_request_method = req_http_request_method
        }
      end)

      it('sets the CORS headers according to the request to accept it', function()
        local cors = CORSPolicy.new()

        cors:header_filter()

        assert.same(req_http_request_headers,
                    ngx.header['Access-Control-Allow-Headers'])
        assert.same(req_http_request_method,
                    ngx.header['Access-Control-Allow-Methods'])
        assert.equals(req_http_origin,
                      ngx.header['Access-Control-Allow-Origin'])
        assert.equals(600,
                      ngx.header['Access-Control-Max-Age'])
        assert.is_true(ngx.header['Access-Control-Allow-Credentials'])
      end)
    end)
  end)
end)
