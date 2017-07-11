local _M = require 'oauth.apicast_oauth'
local test_backend_client = require 'resty.http_ng.backend.test'
local match = require("luassert.match")
local ts = 'threescale_utils'

describe('APIcast Oauth', function()
  local test_backend

  before_each(function() test_backend = test_backend_client.new() end)
  after_each(function() test_backend.verify_no_outstanding_expectations() end)

  describe('.authorize', function()
    it('responds with error when response_type missing', function()
      local apicast_oauth = _M.new()

      ngx.var = { is_args = "?", args = "" }
      stub(ngx.req, 'get_uri_args', function() return { client_id = 'foo', redirect_uri = 'bar' } end)

      stub(_M, 'respond_with_error')
      apicast_oauth.authorize()
      assert.spy(_M.respond_with_error).was.called_with(400, 'invalid_request')
    end)

    it('responds with error when wrong response_type', function()
      local apicast_oauth = _M.new()

      ngx.var = { is_args = "?", args = "" }
      stub(ngx.req, 'get_uri_args', function() return { response_type = 'blah', client_id = 'foo', redirect_uri = 'bar' } end)

      stub(_M, 'respond_with_error')
      apicast_oauth.authorize()
      assert.spy(_M.respond_with_error).was.called_with(400, 'unsupported_response_type')
    end)

    it('responds with error when required params not sent', function()
      local apicast_oauth = _M.new()

      ngx.var = { is_args = "?", args = "" }
      stub(ngx.req, 'get_uri_args', function() return { response_type = 'code', client_id = 'foo'} end)

      stub(_M, 'respond_with_error')
      apicast_oauth.authorize()
      assert.spy(_M.respond_with_error).was.called_with(400, 'invalid_request')
    end)

    it('responds with error when credentials are wrong', function ()
      local apicast_oauth = _M.new()

      stub(_M, 'check_credentials', function () return false end)

      stub(ngx.req, 'get_uri_args', function() return { response_type = 'code', client_id = 'foo', redirect_uri = 'bar' } end)

      stub(_M, 'respond_with_error')
      apicast_oauth.authorize()
      assert.spy(_M.respond_with_error).was.called_with(401, 'invalid_client')
    end)

    it('fails with error when service is missing oauth_login_url', function()
      local apicast_oauth = _M.new()
      local service = { id = 123 }

      stub(_M, 'check_credentials', function () return true end)
      stub(_M, 'check_params', function () return true end)

      stub(ngx.req, 'get_uri_args', function() return { response_type = 'code', client_id = 'foo', redirect_uri = 'bar' } end)

      assert.has_error(function() apicast_oauth:authorize(service) end, "missing oauth login url" )
    end)

    it('redirects to login when all OK', function()
      local apicast_oauth = _M.new()
      local service = { id = 1234, oauth_login_url = "http://example.com/consent"}

      stub(_M, 'check_credentials', function () return true end)
      stub(_M, 'check_params', function () return true end)

      stub(ngx.req, 'get_uri_args', function() return { response_type = 'code', client_id = 'foo', redirect_uri = 'bar' } end)
      stub(ngx, 'redirect')
      ngx.header = { content_type = "application/x-www-form-urlencoded" }
      apicast_oauth:authorize(service)
      assert.spy(ngx.redirect).was.called_with(match.is_string())
    end)
  end)
  
  describe('.callback', function()
    it('responds with error when state is missing', function()
      local apicast_oauth = _M.new()
      
      stub(ngx.req, 'get_uri_args', function() return { code = '123456' } end)
      stub(_M, 'respond_with_error')
      
      apicast_oauth.callback()
      assert.spy(_M.respond_with_error).was.called_with(400, 'invalid_request')
    end)
    
    it('responds with error when state value is invalid', function()
      local apicast_oauth = _M.new()
      
      stub(ngx.req, 'get_uri_args', function() return { code = '123456', state = '987654', redirect_uri = "http://example.com/oauth/callback" } end)
      stub(_M, 'respond_with_error')
      stub(_M, 'check_state', function() return false end)
      
      apicast_oauth.callback()
      assert.spy(_M.respond_with_error).was.called_with(400, 'invalid_state')
    end)
  end)
end)