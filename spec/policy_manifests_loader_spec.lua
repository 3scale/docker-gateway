local policy_manifests_loader = require 'apicast.policy_manifests_loader'

local resty_env = require('resty.env')
local pl_file = require('pl.file')
local cjson = require('cjson')

describe('Policy Manifests Loader', function()
  describe('.get_manifest', function()
    describe('when it is a builtin policy and it exists', function()
      it('returns its manifest', function()
        -- Use the headers policy for testing. It could be any other.
        local manifest_file = 'gateway/src/apicast/policy/headers/apicast-policy.json'
        local headers_string_manifest = pl_file.read(manifest_file)
        local headers_decoded_manifest = cjson.decode(headers_string_manifest)

        local manifest = policy_manifests_loader.get('headers', 'builtin')

        assert.same(headers_decoded_manifest, manifest)
      end)
    end)

    describe('when it is a non-builtin policy and it exists', function()
      before_each(function()
        resty_env.set('APICAST_POLICY_LOAD_PATH', 'spec/fixtures/policies')
      end)

      it('returns its manifest', function()
        local manifest_file = 'spec/fixtures/policies/test/2.0.0-0/apicast-policy.json'
        local test_policy_string_manifest = pl_file.read(manifest_file)
        local test_policy_decoded_manifest = cjson.decode(test_policy_string_manifest)

        local manifest = policy_manifests_loader.get('test', '2.0.0-0')

        assert.same(test_policy_decoded_manifest, manifest)
      end)
    end)

    describe('when the built-in policy does no exist', function()
      it('returns nil', function()
        assert.is_nil(policy_manifests_loader.get('invalid', 'builtin'))
      end)
    end)

    describe('when the non-built-in policy does no exist', function()
      it('returns nil', function()
        assert.is_nil(policy_manifests_loader.get('invalid', '1.0.0'))
      end)
    end)

    describe('when the policy exists but with a different version', function()
      it('returns nil', function()
        assert.is_nil(policy_manifests_loader.get('headers', 'invalid'))
      end)
    end)
  end)
end)
