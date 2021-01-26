local test_backend_client = require 'resty.http_ng.backend.test'
local loader = require 'apicast.configuration_loader.oidc'
local cjson = require('cjson')

describe('OIDC Configuration loader', function()
  describe('.call', function()
    local test_backend
    before_each(function() test_backend = test_backend_client.new() end)
    before_each(function() loader.discovery.http_client.backend = test_backend end)

    it('ignores empty config', function()
      assert.same({}, { loader.call() })
      assert.same({''}, { loader.call('') })
    end)

    it('ignores config without oidc_issuer_endpoint', function()
      local config = cjson.encode{
        services = {
          { id = 21 },
          { id = 42 },
        }
      }

      assert(loader.call(config))
    end)

    it('forwards all parameters', function()
      assert.same({'{"oidc":[]}', 'one', 'two'}, { loader.call('{}', 'one', 'two')})
    end)

    it('gets openid configuration', function()
      local config = {
        services = {
          { id = 21, proxy = { oidc_issuer_endpoint = 'https://user:pass@example.com' } },
        }
      }

      test_backend
        .expect{ url = "https://example.com/.well-known/openid-configuration" }
        .respond_with{
          status = 200,
          headers = { content_type = 'application/json' },
          body = [[{"jwks_uri":"http://example.com/jwks","issuer":"https://example.com"}]],
        }

      test_backend
        .expect{ url = "http://example.com/jwks" }
        .respond_with{
          status = 200,
          headers = { content_type = 'application/json' },
          body = [[{"keys":[]}]],
        }
      local oidc = loader.call(cjson.encode(config))

      assert.same([[{"services":[{"id":21,"proxy":{"oidc_issuer_endpoint":"https:\/\/user:pass@example.com"}}],"oidc":[{"service_id":21,"issuer":"https:\/\/example.com","config":{"jwks_uri":"http:\/\/example.com\/jwks","issuer":"https:\/\/example.com"},"keys":{}}]}]], oidc)
    end)

    -- This is a regression test. cjson crashed when parsing a config where
    -- only some of the services have OIDC enabled. In particular, it crashed
    -- when it tried to convert into JSON a "sparse array":
    -- https://www.kyne.com.au/~mark/software/lua-cjson-manual.html#encode_sparse_array
    -- The easiest way to create a sparse array with the default cjson config
    -- is to create a table that has 11 positions and only the last one is !=
    -- false/nil.
    it('works correctly when only some of the services have OIDC enabled', function()
      local oidc = {}
      for _=1, 10 do table.insert(oidc, false) end
      oidc[11] = { issuer = "https://example.com" }

      local services = {}
      for i=1, 11 do table.insert(services, { id = i }) end

      local config = { services = services, oidc = oidc }

      loader.call(cjson.encode(config))
    end)
  end)
end)
