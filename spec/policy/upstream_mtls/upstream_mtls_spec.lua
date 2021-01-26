local upstream_mtls = require("apicast.policy.upstream_mtls")
local ssl = require('ngx.ssl')

describe('Upstream MTLS policy', function()

  local certificate_path = 't/fixtures/CA/root-ca.crt'
  local certificate_key_path = 't/fixtures/CA/root-ca.key'

  -- Set here the const to not use the pakcage ones, if not test will not fail
  -- if changes0
  local path_type = "path"
  local embedded_type = "embedded"

  before_each(function()
    stub.new(upstream_mtls, 'set_certs', function() return true end)

    spy.on(ssl, "parse_pem_cert")
    spy.on(ssl, "parse_pem_priv_key")
  end)

  describe("read path values", function()

    it("Reads correctly the file path", function()
      local config = {
        certificate = certificate_path,
        certificate_type = path_type,
        certificate_key = certificate_key_path,
        certificate_key_type = path_type,
      }
      local object = upstream_mtls.new(config)
      assert.spy(ssl.parse_pem_cert).was.called()
      assert.spy(ssl.parse_pem_priv_key).was.called()
      assert.truthy(object.cert)
      assert.truthy(object.cert_key)

      spy.on(object, "set_certs")
      object:balancer(context)
      assert.spy(object.set_certs).was.called()
    end)


    it("Not correct path triggers does not load correctly", function()
      local config = {
        certificate = certificate_path .. "invalid",
        certificate_type = path_type,
        certificate_key = certificate_key_path .. "invalid",
        certificate_key_type = path_type,
      }
      local object = upstream_mtls.new(config)
      assert.spy(ssl.parse_pem_cert).was_not_called()
      assert.spy(ssl.parse_pem_priv_key).was_not_called()
      assert.is_falsy(object.cert)
      assert.is_falsy(object.cert_key)

      spy.on(object, "set_certs")
      object:balancer(context)
      assert.spy(object.set_certs).was_not_called()
    end)
  end)

  describe("string config is working correctly", function()

    local embedded_certificate = 'data:application/x-x509-ca-cert;name=server.crt;base64,LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJ1RENDQVY2Z0F3SUJBZ0lRUkdnVjQzVkIvT3RKVkZOY1NpN0tmREFLQmdncWhrak9QUVFEQWpBYU1SZ3cKRmdZRFZRUURFdzlwYm5SbGNtMWxaR2xoZEdVdFkyRXdIaGNOTVRrd05EQTBNVEV6TWpVNVdoY05Namt3TkRBeApNVEV6TWpVNVdqQVJNUTh3RFFZRFZRUURFd1p6WlhKMlpYSXdXVEFUQmdjcWhrak9QUUlCQmdncWhrak9QUU1CCkJ3TkNBQVErcHJkTE9wa2pGbTEvcWg1dnJxQlcyN0hmY0Q0V3psd0lZbHp1S0tDSkZxR1k3YUV3V3B2MjR2QWcKbkxKQlFhZnE4VUNGZ1hVYjNNL3hLYzNKQURwaG80R09NSUdMTUE0R0ExVWREd0VCL3dRRUF3SUZvREFkQmdOVgpIU1VFRmpBVUJnZ3JCZ0VGQlFjREFRWUlLd1lCQlFVSEF3SXdIUVlEVlIwT0JCWUVGSCtKU2VPbjNzaklia0h2CkQ4K3g3YXZNelpsT01COEdBMVVkSXdRWU1CYUFGTm9TTjRwd0pJa1M1UnlmQlNWMTIxZUVxRXh4TUJvR0ExVWQKRVFRVE1CR0NDV3h2WTJGc2FHOXpkSUlFZEdWemREQUtCZ2dxaGtqT1BRUURBZ05JQURCRkFpQVpPMVRIL0tveAowTDhnOTVSZDQ0L1BaN2RxY1FLOXMzaUg3UVEwajlJcmt3SWhBUC9HcnpEQ0xFVmtEZ0JPOW90a3FHWmRHcDF5CkNZQzZBZ0dkQ0ZIYkxQMW4KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
    local embedded_certificate_key = 'data:application/pkcs8;name=server.key;base64,LS0tLS1CRUdJTiBFQyBQUklWQVRFIEtFWS0tLS0tCk1IY0NBUUVFSUxZVmJhUmhSeHZtVmNWTDIxL0REazliQ0k5Y3Y5WjBxQ2pncklocFdJcEdvQW9HQ0NxR1NNNDkKQXdFSG9VUURRZ0FFUHFhM1N6cVpJeFp0ZjZvZWI2NmdWdHV4MzNBK0ZzNWNDR0pjN2lpZ2lSYWhtTzJoTUZxYgo5dUx3SUp5eVFVR242dkZBaFlGMUc5elA4U25OeVFBNllRPT0KLS0tLS1FTkQgRUMgUFJJVkFURSBLRVktLS0tLQo='

    it("Correct certificate read", function()
      local config = {
        certificate = embedded_certificate,
        certificate_type = embedded_type,
        certificate_key = embedded_certificate_key,
        certificate_key_type = embedded_type,
      }
      local object = upstream_mtls.new(config)
      assert.spy(ssl.parse_pem_cert).was.called()
      assert.spy(ssl.parse_pem_priv_key).was.called()
      assert.truthy(object.cert)
      assert.truthy(object.cert_key)

      spy.on(object, "set_certs")
      object:balancer(context)
      assert.spy(object.set_certs).was.called()
    end)

    it("Nil certificate", function()
      local config = {
        certificate = nil,
        certificate_type = embedded_type,
        certificate_key = nil,
        certificate_key_type = embedded_type,
      }
      local object = upstream_mtls.new(config)
      assert.spy(ssl.parse_pem_cert).was_not_called()
      assert.spy(ssl.parse_pem_priv_key).was_not_called()
      assert.falsy(object.cert)
      assert.falsy(object.cert_key)

      spy.on(object, "set_certs")
      object:balancer(context)
      assert.spy(object.set_certs).was_not_called()
    end)

    it("Invalid certificate", function()
      local config = {
        certificate = "XXXX",
        certificate_type = embedded_type,
        certificate_key = "XXXX",
        certificate_key_type = embedded_type,
      }
      local object = upstream_mtls.new(config)
      assert.spy(ssl.parse_pem_cert).was_not_called()
      assert.spy(ssl.parse_pem_priv_key).was_not_called()
      assert.falsy(object.cert)
      assert.falsy(object.cert_key)

      spy.on(object, "set_certs")
      object:balancer(context)
      assert.spy(object.set_certs).was_not_called()
    end)

  end)

end)

