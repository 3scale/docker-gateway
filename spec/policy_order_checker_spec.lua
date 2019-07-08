local policy_manifests_loader = require 'apicast.policy_manifests_loader'
local PolicyOrderChecker = require 'apicast.policy_order_checker'
local IpCheckPolicy = require 'apicast.policy.ip_check'
local HeadersPolicy = require'apicast.policy.headers'
local CORSPolicy = require 'apicast.policy.cors'
local DefaultCredentialsPolicy = require 'apicast.policy.default_credentials'
local APIcastPolicy = require 'apicast.policy.apicast'

describe('Policy Order Checker', function()
  describe('.check', function()
    -- Use the real manifests of the built-in policies
    local manifests = policy_manifests_loader.get_all()

    local order_checker = PolicyOrderChecker.new(manifests)

    before_each(function()
      stub(ngx, 'log')
    end)

    it('does not show errors when there are no policies in the chain', function()
      order_checker:check({})

      assert.stub(ngx.log).was_not_called()
    end)

    it('does not show errors when the chain is nil', function()
      order_checker:check()

      assert.stub(ngx.log).was_not_called()
    end)

    it('does not show errors when there are no order violations', function()
      -- There are no order restrictions between the headers policy and the IP
      -- check one.
      local headers_policy_instance = HeadersPolicy.new({})
      local ip_check_policy_instance = IpCheckPolicy.new(
          { ips = { '1.2.3.4' }, check_type = 'whitelist' }
      )
      local chain = { headers_policy_instance, ip_check_policy_instance }

      order_checker:check(chain)

      assert.stub(ngx.log).was_not_called()
    end)

    it('shows an error when there is a "before" order violation', function()
      -- The CORS policy needs to be placed before the apicast one.
      local apicast_policy_instance = APIcastPolicy.new({})
      local cors_policy_instance = CORSPolicy.new({})
      local chain = { apicast_policy_instance, cors_policy_instance }

      order_checker:check(chain)

      assert.stub(ngx.log).was_called_with(
          ngx.WARN,
          'CORS Policy (version: builtin) should be placed before APIcast (version: builtin)'
      )
    end)

    it('shows an error for each order violation when there are several of them', function()
      -- Both the CORS policy and the default credentials one need to be placed
      -- before the apicast one.
      local apicast_policy_instance = APIcastPolicy.new({})
      local cors_policy_instance = CORSPolicy.new({})
      local default_creds_policy_instance = DefaultCredentialsPolicy.new(
        { auth_type = 'user_key', user_key = 'uk' }
      )
      local chain = {
        apicast_policy_instance,
        cors_policy_instance,
        default_creds_policy_instance
      }

      order_checker:check(chain)

      assert.stub(ngx.log).was_called(2)

      assert.stub(ngx.log).was_called_with(
          ngx.WARN,
          'CORS Policy (version: builtin) should be placed before APIcast (version: builtin)'
      )

      assert.stub(ngx.log).was_called_with(
          ngx.WARN,
          'Default credentials policy (version: builtin) should be placed before APIcast (version: builtin)'
      )
    end)

    it('shows errors when there are several instances of a policy and one of them violates the rules', function()
      -- The CORS policy needs to be placed before the apicast one.
      local cors_policy_instance_1 = CORSPolicy.new({})
      local apicast_policy_instance = APIcastPolicy.new({})
      local cors_policy_instance_2 = CORSPolicy.new({})
      local chain = {
        cors_policy_instance_1,
        apicast_policy_instance,
        cors_policy_instance_2
      }

      order_checker:check(chain)

      assert.stub(ngx.log).was_called(1)
      assert.stub(ngx.log).was_called_with(
          ngx.WARN,
          'CORS Policy (version: builtin) should be placed before APIcast (version: builtin)'
      )
    end)

    it('does no show an error when the version does not match the one in the restriction', function()
      -- The CORS policy needs to be placed before the apicast one (version
      -- 'builtin'). This test instantiates it with a different version to
      -- check that no errors are logged.
      local apicast_policy_instance = APIcastPolicy.new({})
      apicast_policy_instance._VERSION = "0.1"
      local cors_policy_instance = CORSPolicy.new({})
      local chain = { apicast_policy_instance, cors_policy_instance }

      order_checker:check(chain)

      assert.stub(ngx.log).was_not_called()
    end)
  end)
end)
