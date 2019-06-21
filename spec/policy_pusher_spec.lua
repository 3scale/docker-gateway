local PolicyPusher = require('apicast.policy_pusher')

local cjson = require 'cjson'
local http_ng = require 'resty.http_ng'

describe('Policy pusher', function()
  local policy_name = 'test_policy'
  local policy_version = '1.0.0'
  local policy_manifest = { name = 'Test policy', version = '1.0.0' }

  local manifests_loader = {
    get = function(name, version)
      local manifests = {
        [policy_name] = { [policy_version] = policy_manifest }
      }

      return manifests[name][version]
    end
  }

  local admin_portal_domain = 'some-account-admin.3scale.net'
  local access_token = 'my_access_token'

  local test_backend
  local http_client

  before_each(function()
    test_backend = http_ng.backend()
    http_client = http_ng.new({ backend = test_backend })
  end)

  describe('if the policy exists', function()
    it('pushes the policy to the 3scale admin portal', function()
      local request_body = {
        access_token = access_token,
        name = policy_name,
        version = policy_version,
        schema = policy_manifest
      }

      test_backend.expect{
        url = 'https://' .. admin_portal_domain ..
            '/admin/api/registry/policies',
        body = cjson.encode(request_body)
      }.respond_with{ status = 200 }

      local policy_pusher = PolicyPusher.new(http_client, manifests_loader)
      policy_pusher:push(policy_name, policy_version, admin_portal_domain, access_token)
    end)
  end)

  describe('if the policy does no exist', function()
    it('does not push anything to the 3scale admin portal', function()
      local version = 'invalid'

      stub(test_backend, 'send')

      local policy_pusher = PolicyPusher.new(http_client, manifests_loader)
      policy_pusher:push(policy_name, version, admin_portal_domain, access_token)

      assert.stub(test_backend.send).was_not_called()
    end)
  end)

  describe('if the request to 3scale returns an error', function()
    it('shows the error', function()
      stub(ngx, 'log')

      local request_body = {
        access_token = access_token,
        name = policy_name,
        version = policy_version,
        schema = policy_manifest
      }

      local error_msg_returned = 'Some error'

      test_backend.expect{
        url = 'https://' .. admin_portal_domain ..
            '/admin/api/registry/policies',
        body = cjson.encode(request_body)
      }.respond_with{ status = 400, body = error_msg_returned }

      local policy_pusher = PolicyPusher.new(http_client, manifests_loader)
      policy_pusher:push(policy_name, policy_version, admin_portal_domain, access_token)

      assert.stub(ngx.log).was_called_with(
        ngx.ERR, 'Error while pushing the policy: ', error_msg_returned
      )
    end)
  end)
end)
