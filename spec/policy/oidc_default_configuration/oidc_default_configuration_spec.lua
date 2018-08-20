local _M = require('apicast.policy.oidc_default_configuration')
local Service = require('apicast.configuration.service')
describe('oidc_default_configuration policy', function()
  describe('.new', function()
    it('works without configuration', function()
      assert(_M.new())
    end)

    it('accepts empty configuration', function()
        assert(_M.new({ }))
    end)

    it('accepts configuration with overrides', function()
      local overrides = {
        { key = 'public_key', value ='MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAi7t6m4d/02dZ8dOe+DFcuUYiOWueHlNkFwdUfOs06eUETOV6Y9WCXu3D71dbF0Fhou69ez5c3HAZrSVS2qC1Htw9NkVlLDeED7qwQQMmSr7RFYNQ6BYekAtn/ScFHpq8Tx4BzhcDb6P0+PHCo+bkQedxwhbMD412KSM2UAVQaZ+TW+ngdaaVEs1Cgl4b8xxZ9ZuApXZfpddNdgvjBeeYQbZnaqU3b0P5YE0s0YvIQqYmTjxh4RyLfkt6s/BS1obWUOC+0ChRWlpWE7QTEVEWJP5yt8hgZ5MecTmBi3yZ/0ts3NsL83413NdbWYh+ChtP696mZbJozflF8jR9pewTbQIDAQAB'}
      }
      local policy = _M.new{ overrides = overrides }

      assert.same(overrides, policy.overrides)
    end)
  end)

  describe(':rewrite', function()
    local context
    before_each(function() context = nil end)

    describe('when service has oidc configuration', function()
      before_each(function()
        context = {
          service = Service.new{ oidc = { config = {} } }
        }
      end)

      it('overrides fields in the oidc configuration', function()
        local policy = _M.new{ overrides = { { key = 'public_key', value = 'somevalue' } }}

        policy:rewrite(context)


        assert.equal('somevalue', context.service.oidc.config.public_key)
      end)
    end)

    describe('when does not have oidc configuration', function()
      before_each(function()
        context = {
          service = Service.new{ oidc = {  } }
        }
      end)

      it('overrides fields in the oidc configuration', function()
        local policy = _M.new{ overrides = { { key = 'public_key', value = 'somevalue' } }}

        policy:rewrite(context)

        assert.is_nil(context.service.oidc.config)
      end)

    end)
  end)
end)
