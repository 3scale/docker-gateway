local _M = require 'configuration_loader.remote_v2'
local test_backend_client = require 'resty.http_ng.backend.test'
local cjson = require 'cjson'
local user_agent = require 'user_agent'
local env = require 'resty.env'

describe('Configuration Remote Loader V2', function()

  local test_backend
  local loader

  before_each(function() test_backend = test_backend_client.new() end)
  before_each(function()
    loader = _M.new('http://example.com', { client = test_backend })
  end)

  after_each(function() test_backend.verify_no_outstanding_expectations() end)

  describe('loader without endpoint', function()
    before_each(function() loader = _M.new() end)

    it('wont crash when getting services', function()
      assert.same({ nil, 'no endpoint' }, { loader:services() })
    end)

    it('wont crash when getting config', function()
      assert.same({ nil, 'no endpoint' }, { loader:config() })
    end)
  end)

  describe('http_client #http', function()
    it('has correct user agent', function()
      test_backend.expect{ url = 'http://example.com/t', headers = { ['User-Agent'] = tostring(user_agent) } }
        .respond_with{ status = 200  }

      local res, err = loader.http_client.get('http://example.com/t')

      assert.falsy(err)
      assert.equal(200, res.status)
    end)
  end)

  describe(':services', function()
    it('retuns list of services', function()
      test_backend.expect{ url = 'http://example.com/admin/api/services.json' }.
        respond_with{ status = 200, body = cjson.encode({ services = {
            { service = { id = 1 }},
            { service = { id = 2 }}
          }})
        }

      local services = loader:services()

      assert.truthy(services)
      assert.equal(2, #services)
    end)

    it('returns list of services when APICAST_SERVICES is set', function()
      env.set('APICAST_SERVICES', '11,42')

      local services = loader:services()

      assert.truthy(services)
      assert.equal(2, #services)
      assert.same({ { service = { id = 11 } }, { service = { id = 42 } } }, services)
    end)

    it('ignores APICAST_SERVICES when empty', function()
      env.set('APICAST_SERVICES', '')

      test_backend.expect{ url = "http://example.com/admin/api/services.json" }.
        respond_with{ status = 200, body = cjson.encode({ services = { { service = { id = 1 }} }}) }

      local services = loader:services()

      assert.truthy(services)
      assert.equal(1, #services)
      assert.same({ { service = { id = 1 } } }, services)
    end)
  end)

  describe(':config', function()
    it('loads a configuration', function()
      test_backend.expect{ url = 'http://example.com/admin/api/services/42/proxy/configs/sandbox/latest.json' }.
        respond_with{ status = 200, body = cjson.encode(
          {
            proxy_config = {
              version = 13,
              environment = 'sandbox',
              content = { id = 42, backend_version = 1, proxy = { oidc_issuer_endpoint = ngx.null } }
            }
          }
        ) }
      local service = { id = 42 }

      local config = loader:config(service, 'sandbox', 'latest')

      assert.truthy(config)
      assert.equal('table', type(config.content))
      assert.equal(13, config.version)
      assert.equal('sandbox', config.environment)
    end)

    it('takes version from the environment', function()
      test_backend.expect{ url = 'http://example.com/admin/api/services/42/proxy/configs/sandbox/2.json' }.
      respond_with{ status = 200, body = cjson.encode(
        {
          proxy_config = {
            version = 2,
            environment = 'sandbox',
            content = { id = 42, backend_version = 1 }
          }
        }
      ) }
      local service = { id = 42 }

      env.set('APICAST_SERVICE_42_CONFIGURATION_VERSION', '2')
      local config = loader:config(service, 'sandbox', 'latest')

      assert.truthy(config)
      assert.equal('table', type(config.content))
      assert.equal(2, config.version)
      assert.equal('sandbox', config.environment)
    end)

    it('includes OIDC configuration', function()
      test_backend.expect{ url = 'http://example.com/admin/api/services/42/proxy/configs/staging/latest.json' }.
      respond_with{ status = 200, body = cjson.encode(
        {
          proxy_config = {
            version = 2,
            environment = 'sandbox',
            content = {
              id = 42, backend_version = 1,
              proxy = { oidc_issuer_endpoint = 'http://admin:password@idp.example.com/auth/realms/foo/' }
            }
          }
        }
      ) }

      test_backend.expect{ url = "http://idp.example.com/auth/realms/foo/.well-known/openid-configuration" }.
        respond_with{
          status = 200,
          headers = { content_type = 'application/json' },
          body = [[
            {
              "issuer": "https://idp.example.com/auth/realms/foo",
              "id_token_signing_alg_values_supported": [ "RS256" ]
            }
          ]]
      }
      test_backend.expect{ url = "https://idp.example.com/auth/realms/foo" }.
        respond_with{
          status = 200,
          headers = { content_type = 'application/json' },
          body =  [[
            { "public_key": "foobar" }
          ]]
      }

      local config = assert(loader:config({ id = 42 }, 'staging', 'latest'))

      assert.same({
        config = {
          openid = {
            client_id = 'admin',
            client_secret = 'password',
            id_token_signing_alg_values_supported = { 'RS256' },
            issuer = 'https://idp.example.com/auth/realms/foo',
          },
          public_key = "foobar",
        },
        issuer = 'https://idp.example.com/auth/realms/foo',
      }, config.oidc)
    end)
  end)

  describe(':call', function()
    it('returns configuration for all services', function()
      test_backend.expect{ url = 'http://example.com/admin/api/services.json' }.
        respond_with{ status = 200, body = cjson.encode({ services = {
            { service = { id = 1 }},
            { service = { id = 2 }}
          }})
        }
      test_backend.expect{ url = 'http://example.com/admin/api/services/1/proxy/configs/staging/latest.json' }.
        respond_with{ status = 200, body = cjson.encode(
          {
            proxy_config = {
              version = 13,
              environment = 'staging',
              content = { id = 1, backend_version = 1 }
            }
          }
        )}
      test_backend.expect{ url = 'http://example.com/admin/api/services/2/proxy/configs/staging/latest.json' }.
        respond_with{ status = 200, body = cjson.encode(
          {
            proxy_config = {
              version = 42,
              environment = 'staging',
              content = { id = 2, backend_version = 2 }
            }
          }
        )}

      local config = assert(loader:call('staging'))

      assert.truthy(config)
      assert.equals('string', type(config))

      assert.equals(2, #(cjson.decode(config).services))
    end)

    it('does not crash on error when getting services', function()
      test_backend.expect{ url = 'http://example.com/admin/api/services.json' }.
        respond_with{ status = 404 }

      local config, err = loader:call('staging')

      assert.falsy(config)
      assert.equal('invalid status: 404 (Not Found)', tostring(err))
    end)

    it('returns simple message on undefined errors', function()
      test_backend.expect{ url = 'http://example.com/admin/api/services.json' }.
      respond_with{ status = 412 }

      local config, err = loader:call('staging')

      assert.falsy(config)
      assert.equal('invalid status: 412', tostring(err))
    end)

    it('returns configuration even when some services are missing', function()
      test_backend.expect{ url = 'http://example.com/admin/api/services.json' }.
        respond_with{ status = 200, body = cjson.encode({ services = {
            { service = { id = 1 }},
            { service = { id = 2 }}
          }})
        }
      test_backend.expect{ url = 'http://example.com/admin/api/services/1/proxy/configs/staging/latest.json' }.
        respond_with{ status = 200, body = cjson.encode(
          {
            proxy_config = {
              version = 13,
              environment = 'staging',
              content = { id = 1, backend_version = 1 }
            }
          }
        )}
      test_backend.expect{ url = 'http://example.com/admin/api/services/2/proxy/configs/staging/latest.json' }.
        respond_with{ status = 404 }

      local config = assert(loader:call('staging'))

      assert.truthy(config)
      assert.equals('string', type(config))

      assert.equals(1, #(cjson.decode(config).services))
    end)
  end)

  describe(':oidc_issuer_configuration', function()
    it('does not crash on empty issuer', function()
      local service = { oidc = { issuer_endpoint = '' }}

      assert.falsy(loader:oidc_issuer_configuration(service))
    end)
  end)

  describe(':index', function()
    before_each(function()
      loader = _M.new('http://example.com/something/with/path', { client = test_backend })
    end)

    it('returns configuration for all services', function()
      env.set('THREESCALE_DEPLOYMENT_ENV', 'production')
      test_backend.expect{ url = 'http://example.com/something/with/path/production.json?host=foobar.example.com' }.
        respond_with{ status = 200, body = cjson.encode({ proxy_configs = {
          {
            proxy_config = {
              version = 42,
              environment = 'staging',
              content = { id = 2, backend_version = 2 }
            }
          }
        }})}

      local config = assert(loader:index('foobar.example.com'))

      assert.truthy(config)
      assert.equals('string', type(config))

      assert.equals(1, #(cjson.decode(config).services))
    end)
  end)

  describe('.call', function()
    it('gets environment from ENV', function()
      local _, err = loader.call()
      assert.equal('missing environment', err)
    end)
  end)
end)
