local _M = require('apicast.policy.oauth_mtls')
local client = assert(fixture('CA', 'client.crt'))
local X509 = require('resty.openssl.x509')
local b64 = require('ngx.base64')

local header_parameter = 'x5t#S256'
local context = {}

local function jwt_cnf()
  return { [header_parameter] = b64.encode_base64url(X509.parse_pem_cert(client):digest('SHA256')) }
end

describe('oauth_mtls policy', function()
  describe('.new', function()
    it('works without configuration', function()
      assert(_M.new())
    end)
  end)

  describe('.access', function()
    before_each(function()
      context = {
        jwt = {},
        service = {
          id = 4,
          auth_failed_status = 403,
          error_auth_failed = 'auth failed',
          auth_failed_headers = 'text/plain; charset=utf-8'
        }
      }

      ngx.header = {}
      stub(ngx, 'print')
      stub(ngx, 'exit')
      context.jwt = {}
    end)

    it('accepts when the digest equals cnf claim', function()
      ngx.var = { ssl_client_raw_cert = client }

      context.jwt.cnf = jwt_cnf()

      local policy = _M.new()

      assert.is_true(policy:access(context))
    end)

    it('rejects when the digest not equals cnf claim', function()
      ngx.var = { ssl_client_raw_cert = client }

      context.jwt.cnf = {}
      context.jwt.cnf[header_parameter] = 'invalid_digest'

      local policy = _M.new()
      policy:access(context)

      assert.stub(ngx.exit).was_called_with(ngx.HTTP_UNAUTHORIZED)
      assert.stub(ngx.print).was_called_with('{"error": "invalid_token"}')
    end)

    it('rejects when the client certificate not found', function()
      ngx.var = { ssl_client_raw_cert = nil }

      context.jwt.cnf = jwt_cnf()

      local policy = _M.new()
      policy:access(context)

      assert.stub(ngx.exit).was_called_with(ngx.HTTP_UNAUTHORIZED)
      assert.stub(ngx.print).was_called_with('{"error": "invalid_token"}')
    end)

    it('rejects when the cnf claim not defined', function()
      ngx.var = { ssl_client_raw_cert = client }

      local policy = _M.new()
      policy:access(context)

      assert.stub(ngx.exit).was_called_with(ngx.HTTP_UNAUTHORIZED)
      assert.stub(ngx.print).was_called_with('{"error": "invalid_token"}')
    end)

    it('rejects when the cnf claim not defined and context.service is nil', function()
      ngx.var = { ssl_client_raw_cert = client }

      local policy = _M.new()
      context.service = nil
      policy:access(context)

      assert.stub(ngx.exit).was_called_with(ngx.HTTP_UNAUTHORIZED)
      assert.stub(ngx.print).was_called_with('{"error": "invalid_token"}')
    end)

  end)
end)
