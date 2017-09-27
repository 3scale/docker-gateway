local _M = require('oauth.oidc')

local jwt_validators = require('resty.jwt-validators')
local jwt = require('resty.jwt')

local rsa = require('fixtures.rsa')
local test_backend_client = require('resty.http_ng.backend.test')
local cjson = require 'cjson'

describe('OIDC', function()

  describe(':transform_credentials', function()
    local service = {
      id = 1,
      oidc = {
        issuer = 'https://example.com/auth/realms/apicast',
        config = { public_key = rsa.pub, openid = { id_token_signing_alg_values_supported = { 'RS256' } } }
      }
    }

    before_each(function() jwt_validators.set_system_clock(function() return 0 end) end)

    it('successfully verifies token', function()
      local oidc = _M.new(service)
      local access_token = jwt:sign(rsa.private, {
        header = { typ = 'JWT', alg = 'RS256' },
        payload = {
          iss = service.oidc.issuer,
          aud = 'notused',
          azp = 'ce3b2e5e',
          nbf = 0,
          exp = ngx.now() + 10,
        },
      })

      local credentials, ttl, err = oidc:transform_credentials({ access_token = access_token })

      assert(credentials, err)

      assert.same({ app_id  = "ce3b2e5e" }, credentials)
      assert.equal(10, ttl)
    end)

    it('caches verification', function()
      local oidc = _M.new(service)
      local access_token = jwt:sign(rsa.private, {
        header = { typ = 'JWT', alg = 'RS256' },
        payload = {
          iss = service.oidc.issuer,
          aud = {'ce3b2e5e','notused'},
          nbf = 0,
          exp = ngx.now() + 10,
        },
      })

      local stubbed
      for _=1, 10 do
        local credentials, _, err = oidc:transform_credentials({ access_token = access_token })
        if not stubbed then
          stubbed = stub(jwt, 'verify_jwt_obj', function(_, jwt_obj, _) return jwt_obj end)
        end
        assert(credentials, err)

        assert.same({ app_id  = "ce3b2e5e" }, credentials)
      end
    end)

    it('verifies iss', function()
      local oidc = _M.new(service)
      local access_token = jwt:sign(rsa.private, {
        header = { typ = 'JWT', alg = 'RS256' },
        payload = {
          iss = service.oidc.issuer,
          aud = 'foobar',
          nbf = 0,
          exp = ngx.now() + 10,
        },
      })

      local credentials, _, err = oidc:transform_credentials({ access_token = access_token })

      assert(credentials, err)
    end)


    it('verifies nbf', function()
      local oidc = _M.new(service)
      local access_token = jwt:sign(rsa.private, {
        header = { typ = 'JWT', alg = 'RS256' },
        payload = {
          iss = service.oidc.issuer,
          aud = 'foobar',
          nbf = 1,
          exp = ngx.now() + 10,
        },
      })

      local credentials, _, err = oidc:transform_credentials({ access_token = access_token })

      assert.falsy(credentials)
      assert.truthy(err)
    end)

    it('verifies exp', function()
      local oidc = _M.new(service)
      local access_token = jwt:sign(rsa.private, {
        header = { typ = 'JWT', alg = 'RS256' },
        payload = {
          iss = service.oidc.issuer,
          aud = 'foobar',
          nbf = 0,
          exp = 1,
        },
      })

      jwt_validators.set_system_clock(function() return 0 end)

      local credentials, _, err = oidc:transform_credentials({ access_token = access_token })
      assert(credentials, err)

      jwt_validators.set_system_clock(function() return 1 end)

      credentials, _, err = oidc:transform_credentials({ access_token = access_token })

      assert.falsy(credentials, err)
    end)

    it('verifies alg', function()
      local oidc = _M.new(service)
      local access_token = jwt:sign(rsa.private, {
        header = { typ = 'JWT', alg = 'HS256' },
        payload = { },
      })

      local credentials, _, err = oidc:transform_credentials({ access_token = access_token })

      assert.match('invalid alg', err, nil, true)
      assert.falsy(credentials, err)
    end)
  end)

  describe(':transform_credentials with token introspection', function() 
    local access_token = jwt:sign(rsa.private, {
        header = { typ = 'JWT', alg = 'RS256' },
        payload = {
          iss = 'https://example.com/auth/realms/apicast',
          aud = 'foobar',
          nbf = 0,
          exp = ngx.now() + 10,
        },
      })
    local service =  {
      id = 2,
      oidc = {
        issuer = 'https://example.com/auth/realms/apicast',
        config = {
          public_key = rsa.pub,
          openid = {
            id_token_signing_alg_values_supported = { 'RS256' },
            token_introspection_endpoint = 'https://example.com/auth/realms/apicast/token/introspection',
            end_session_endpoint = 'https://example.com/auth/realms/apicast/logout',
          }
        }
      },
      extract_credentials = function() 
        return { ['access_token'] = access_token }
      end
    }
    local test_backend

    before_each(function() jwt_validators.set_system_clock(function() return 0 end) end)
    before_each(function() 
      test_backend = test_backend_client.new()
    end)

    
    it('executes token introspection to idp if enabled', function() 
      local oidc = _M.new(service, {client = test_backend, introspection_enabled = true})
      test_backend.expect{ url = 'https://example.com/auth/realms/apicast/token/introspection' }.
        respond_with{
          status = 200,
          body = cjson.encode({
              active = true
          })
        }
      -- call token introspection and cache results
      local credentials,_,err = oidc:transform_credentials({access_token = access_token})
      assert(credentials, err)
      assert.same({ app_id = 'foobar'}, credentials)
      
      -- and do not call twice if caching results
      credentials, _, err = oidc:transform_credentials({access_token = access_token})
      assert.same({ app_id = 'foobar'}, credentials)
      test_backend.verify_no_outstanding_expectations()
    end)

    it('fails transform_credentials after revoke', function() 
      local oidc = _M.new(service, {client = test_backend, introspection_enabled = true})
      test_backend.expect{ url = 'https://example.com/auth/realms/apicast/token/introspection' }.
        respond_with {
          status = 200,
          body = cjson.encode({
            active = true
          })
        }
      test_backend.expect{ url = 'https://example.com/auth/realms/apicast/logout' }.
        respond_with {
          status = 204,
          body = ""
        }
      stub(ngx, 'say')
      stub(ngx, 'exit')
      stub(ngx.req , 'read_body')
      stub(ngx.req , 'get_body_data')
      stub(ngx, 'decode_args', function() return {refresh_token = ""} end)
      local credentials,_,err = oidc:transform_credentials({access_token = access_token})
      assert(credentials, err)
      assert.same({ app_id = 'foobar'}, credentials)

      oidc:revoke_credentials(service)
      credentials,_,err = oidc:transform_credentials({access_token = access_token})
      assert.falsy(credential)
      assert.truthy(err)
      test_backend.verify_no_outstanding_expectations()
    end)

    it('fails transform_credentials if token is not active', function() 
      local oidc = _M.new(service, {client = test_backend, introspection_enabled = true})
      test_backend.expect{ url = 'https://example.com/auth/realms/apicast/token/introspection' }.
        respond_with{
          status = 200,
          body = cjson.encode({
              active = false
          })
        }
      local credentials,_,err = oidc:transform_credentials({access_token = access_token})
      assert.falsy(credential)
      assert.truthy(err)
      test_backend.verify_no_outstanding_expectations()
    end)

  end)

end)
