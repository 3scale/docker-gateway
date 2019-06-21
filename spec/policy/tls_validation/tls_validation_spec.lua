local _M = require('apicast.policy.tls_validation')

local server = assert(fixture('CA', 'server.crt'))
local CA = assert(fixture('CA', 'intermediate-ca.crt'))
local client = assert(fixture('CA', 'client.crt'))

describe('tls_validation policy', function()
  describe('.new', function()
    it('works without configuration', function()
      assert(_M.new())
    end)

    it('accepts configuration', function()
      assert(_M.new({
        whitelist = {
          { pem_certificate = [[--BEGIN CERTIFICATE--]] }
        }
      }))
    end)
  end)

  describe(':access', function()
    before_each(function()
      stub(ngx, 'say')
      stub(ngx, 'exit')
    end)

    it('rejects non whitelisted certificate', function()
      ngx.var = { ssl_client_raw_cert = client }

      local policy = _M.new({ whitelist = { { pem_certificate = server }}})

      policy:access()

      assert.stub(ngx.exit).was_called_with(400)
      assert.stub(ngx.say).was_called_with('unable to get local issuer certificate')
    end)

    it('rejects certificates that are not valid yet', function()
      local policy = _M.new({ whitelist = { { pem_certificate = client }}})
      policy.x509_store:set_time(os.time{ year = 2000, month = 01, day = 01 })
      ngx.var = { ssl_client_raw_cert = client }

      policy:access()

      assert.stub(ngx.say).was_called_with('certificate is not yet valid')
    end)

    it('rejects certificates that are not longer valid', function()
      local policy = _M.new({ whitelist = { { pem_certificate = client }}})
      policy.x509_store:set_time(os.time{ year = 2042, month = 01, day = 01 })
      ngx.var = { ssl_client_raw_cert = client }

      policy:access()

      assert.stub(ngx.say).was_called_with([[certificate has expired]])
    end)

    it('accepts whitelisted certificate', function()
      ngx.var = { ssl_client_raw_cert = client }

      local policy = _M.new({ whitelist = { { pem_certificate = client }}})

      assert.is_true(policy:access())
    end)

    it('accepts whitelisted CA', function()
      ngx.var = { ssl_client_raw_cert = client }

      local policy = _M.new({ whitelist = { { pem_certificate = CA }}})

      assert.is_true(policy:access())
    end)
  end)
end)
