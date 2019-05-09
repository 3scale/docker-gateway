local _M = require('apicast.oauth.oidc')

local jwt_validators = require('resty.jwt-validators')
local jwt = require('resty.jwt')

local rsa = require('fixtures.rsa')
local ngx_variable = require('apicast.policy.ngx_variable')

describe('OIDC', function()

  describe('.new', function()
    it('returns error when issuer is missing', function()
      local oidc, err = _M.new({
        config = { id_token_signing_alg_values_supported = { 'RS256' } }
      })

      assert(oidc, 'still returns oidc object')
      assert.equal('missing OIDC configuration', err)
    end)

    it('returns error when supported algorithms are missing', function()
      local oidc, err = _M.new({
        issuer = 'http://example.com',
        config = { id_token_signing_alg_values_supported = {} }
      })

      assert(oidc, 'still returns oidc object')
      assert.equal('missing OIDC configuration', err)
    end)

    it('returns no error with valid OIDC configuration', function()
      local oidc, err = _M.new({
        issuer = 'http://example.com',
        config = { id_token_signing_alg_values_supported = { 'RS256' } }
      })

      assert(oidc, 'still returns oidc object')
      assert.falsy(err)
    end)
  end)

  describe(':transform_credentials', function()
    local oidc_config = {
      issuer = 'https://example.com/auth/realms/apicast',
      config = { id_token_signing_alg_values_supported = { 'RS256' } },
      keys = { somekid = { pem = rsa.pub } },
    }

    before_each(function() jwt_validators.set_system_clock(function() return 0 end) end)

    it('successfully verifies token', function()
      local oidc = _M.new(oidc_config)
      local access_token = jwt:sign(rsa.private, {
        header = { typ = 'JWT', alg = 'RS256', kid = 'somekid' },
        payload = {
          iss = oidc_config.issuer,
          aud = 'notused',
          azp = 'ce3b2e5e',
          sub = 'someone',
          exp = ngx.now() + 10,
        },
      })

      local credentials, ttl, _, err = oidc:transform_credentials({ access_token = access_token })

      assert(credentials, err)

      assert.same({ app_id  = "ce3b2e5e" }, credentials)
      assert.equal(10, ttl)
    end)

    it('caches verification', function()
      local oidc = _M.new(oidc_config)
      local access_token = jwt:sign(rsa.private, {
        header = { typ = 'JWT', alg = 'RS256', kid = 'somekid' },
        payload = {
          iss = oidc_config.issuer,
          aud = {'notused'},
          azp = 'ce3b2e5e',
          sub = 'someone',
          exp = ngx.now() + 10,
        },
      })

      local stubbed
      for _=1, 10 do
        local credentials, _, _, err = oidc:transform_credentials({ access_token = access_token })
        if not stubbed then
          stubbed = stub(jwt, 'verify_jwt_obj', function(_, jwt_obj, _) return jwt_obj end)
        end
        assert(credentials, err)

        assert.same({ app_id  = "ce3b2e5e" }, credentials)
      end

      assert.stub(stubbed).was_not_called()
    end)

    it('verifies iss', function()
      local oidc = _M.new(oidc_config)
      local access_token = jwt:sign(rsa.private, {
        header = { typ = 'JWT', alg = 'RS256', kid = 'somekid' },
        payload = {
          iss = oidc_config.issuer,
          aud = 'foobar',
          sub = 'someone',
          exp = ngx.now() + 10,
        },
      })

      local credentials, _, _, err = oidc:transform_credentials({ access_token = access_token })

      assert(credentials, err)
    end)


    it('verifies nbf', function()
      local now = 1123744391
      stub(ngx, 'now', now)

      local oidc = _M.new(oidc_config)
      local access_token = jwt:sign(rsa.private, {
        header = { typ = 'JWT', alg = 'RS256', kid = 'somekid' },
        payload = {
          iss = oidc_config.issuer,
          aud = 'foobar',
          sub = 'someone',
          nbf = now + 5,
          exp = now + 10,
        },
      })

      local credentials, _, _, err = oidc:transform_credentials({ access_token = access_token })

      assert.returns_error([['nbf' claim not valid until ]] .. ngx.http_time(now + 5), credentials, err)
    end)

    it('verifies iat', function()
      local oidc = _M.new(oidc_config)
      local access_token = jwt:sign(rsa.private, {
        header = { typ = 'JWT', alg = 'RS256', kid = 'somekid' },
        payload = {
          iss = oidc_config.issuer,
          aud = 'foobar',
          sub = 'someone',
          iat = 0,
          exp = ngx.now() + 10,
        },
      })

      local credentials, _, _, err = oidc:transform_credentials({ access_token = access_token })

      assert.returns_error([[Claim 'iat' ('0') returned failure]], credentials, err)
    end)

    it('verifies exp', function()
      local oidc = _M.new(oidc_config, {})
      local access_token = jwt:sign(rsa.private, {
        header = { typ = 'JWT', alg = 'RS256', kid = 'somekid' },
        payload = {
          iss = oidc_config.issuer,
          aud = 'foobar',
          sub = 'someone',
          exp = 1,
        },
      })

      jwt_validators.set_system_clock(function() return 0 end)

      local credentials, _, _, err = oidc:transform_credentials({ access_token = access_token })
      assert(credentials, err)

      jwt_validators.set_system_clock(function() return 1 end)

      credentials, _, err = oidc:transform_credentials({ access_token = access_token })

      assert.falsy(credentials, err)
    end)

    it('verifies alg', function()
      local oidc = _M.new(oidc_config)
      local access_token = jwt:sign(rsa.private, {
        header = { typ = 'JWT', alg = 'HS256' },
        payload = { },
      })

      local credentials, _, _, err = oidc:transform_credentials({ access_token = access_token })

      assert.match('invalid alg', err, nil, true)
      assert.falsy(credentials, err)
    end)

    it('validation fails when typ is invalid', function()
      local oidc = _M.new(oidc_config)
      local access_token = jwt:sign(rsa.private, {
        header = { typ = 'JWT', alg = 'RS256', kid = 'somekid' },
        payload = {
          iss = oidc_config.issuer,
          aud = 'notused',
          azp = 'ce3b2e5e',
          sub = 'someone',
          nbf = 0,
          exp = ngx.now() + 10,
          typ = 'Not-Bearer'
        },
      })

      local credentials, _, _, err = oidc:transform_credentials({ access_token = access_token })
      assert.same("Claim 'typ' ('Not-Bearer') returned failure", err)
      assert.falsy(credentials, err)
    end)

    it('validation is successful when typ is included and is Bearer', function()
      local oidc = _M.new(oidc_config)
      local access_token = jwt:sign(rsa.private, {
        header = { typ = 'JWT', alg = 'RS256', kid = 'somekid' },
        payload = {
          iss = oidc_config.issuer,
          aud = 'notused',
          azp = 'ce3b2e5e',
          sub = 'someone',
          nbf = 0,
          exp = ngx.now() + 10,
          typ = 'Bearer'
        },
      })

      local credentials, _, _, err = oidc:transform_credentials({ access_token = access_token })
      assert(credentials, err)
    end)

    describe('getting client_id from any JWT claim', function()

      before_each(function()
        stub(ngx_variable, 'available_context', function(context) return context end)
      end)

      it('use liquid template to modify app_id', function()

        local oidc_config = {
          issuer = 'https://example.com/auth/realms/apicast',
          config = { id_token_signing_alg_values_supported = { 'RS256' } },
          keys = { somekid = { pem = rsa.pub } },
          client_id = "{{aud}}"}
        local oidc = _M.new(oidc_config)

        local access_token = jwt:sign(rsa.private, {
          header = { typ = 'JWT', alg = 'RS256', kid = 'somekid' },
          payload = {
            iss = oidc_config.issuer,
            aud = 'foo',
            azp = 'ce3b2e5e',
            sub = 'someone',
            exp = ngx.now() + 10,
          },
        })

        local credentials, ttl, _, err = oidc:transform_credentials({ access_token = access_token })

        assert(credentials, err)

        assert.same({ app_id  = "foo" }, credentials)
        assert.equal(10, ttl)
      end)

      it('use liquid template functions to modify app_id', function()

        local oidc_config = {
          issuer = 'https://example.com/auth/realms/apicast',
          config = { id_token_signing_alg_values_supported = { 'RS256' } },
          keys = { somekid = { pem = rsa.pub } },
          client_id = "{{ custom | first}}"}
        local oidc = _M.new(oidc_config)
        local access_token = jwt:sign(rsa.private, {
          header = { typ = 'JWT', alg = 'RS256', kid = 'somekid' },
          payload = {
            iss = oidc_config.issuer,
            aud = 'notused',
            azp = 'ce3b2e5e',
            sub = 'someone',
            custom = {"foo", "bar"},
            exp = ngx.now() + 10,
          },
        })

        local credentials, ttl, _, err = oidc:transform_credentials({ access_token = access_token })

        assert(credentials, err)

        assert.same({ app_id  = "foo" }, credentials)
        assert.equal(10, ttl)
      end)

    end)

  end)

end)
