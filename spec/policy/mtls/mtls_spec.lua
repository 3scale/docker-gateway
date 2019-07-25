local _M = require('apicast.policy.mtls')
local X509 = require('resty.openssl.x509')
local client = assert(fixture('CA', 'client.crt'))

local context = {
  jwt = {},
  service = {
    auth_failed_status = 403,
    error_auth_failed = 'auth failed',
    auth_failed_headers = 'text/plain; charset=utf-8'
  }
}

describe('mtls policy', function()
  describe('.new', function()
    it('works without configuration', function()
      assert(_M.new())
    end)
  end)

  describe(':access', function()
    before_each(function()
      ngx.header = {}
      stub(ngx, 'print')
      stub(ngx, 'exit')
      context.jwt = {}
    end)

    it('accepts when the digest equals cnf claim', function()
      ngx.var = { ssl_client_raw_cert = client }

      context.jwt.cnf = {}
      context.jwt.cnf['x5t#S256'] = 'Y4/LVlkpE6qkscPbtoKm3iiKBgfwbOfbdKBEdnZ6ZPY'

      local policy = _M.new()

      assert.is_true(policy:access(context))
    end)

    it('rejects when the digest not equals cnf claim', function()
      ngx.var = { ssl_client_raw_cert = client }

      context.jwt.cnf = {}
      context.jwt.cnf['x5t#S256'] = 'invalid_digest'

      local policy = _M.new()
      policy:access(context)

      assert.stub(ngx.exit).was_called_with(403)
      assert.stub(ngx.print).was_called_with('auth failed')
    end)

    it('rejects when the client certificate not found', function()
      ngx.var = { ssl_client_raw_cert = nil }

      context.jwt.cnf = {}
      context.jwt.cnf['x5t#S256'] = 'Y4/LVlkpE6qkscPbtoKm3iiKBgfwbOfbdKBEdnZ6ZPY'

      local policy = _M.new()
      policy:access(context)

      assert.stub(ngx.exit).was_called_with(403)
      assert.stub(ngx.print).was_called_with('auth failed')
    end)

    it('rejects when the cnf claim not defined', function()
      ngx.var = { ssl_client_raw_cert = client }

      local policy = _M.new()
      policy:access(context)

      assert.stub(ngx.exit).was_called_with(403)
      assert.stub(ngx.print).was_called_with('auth failed')
    end)

  end)
end)
