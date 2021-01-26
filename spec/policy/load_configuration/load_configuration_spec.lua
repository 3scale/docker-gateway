describe('load_configuration', function()
  describe('.new', function()
    it('initializes the policy with a configuration')
    local load_config_policy = require('apicast.policy.load_configuration').new()
    assert.not_nil(load_config_policy)
  end)

  describe('.export', function()
    it('returns a table with the configuration of the policy', function()
      local load_config_policy = require('apicast.policy.load_configuration').new()
      assert.same(load_config_policy.configuration , load_config_policy:export().configuration)
    end)
  end)

  -- TODO: test .init(), .init_worker(), and .rewrite(). Right now it is
  -- difficult because of the coupling with configuration_store.
end)
