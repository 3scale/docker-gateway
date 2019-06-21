local policy = require 'apicast.policy'
local tab_clone = require('table.clone')

describe('policy', function()
  local phases = {
    'init', 'init_worker',
    'rewrite', 'access',
    'content', 'balancer',
    'header_filter', 'body_filter',
    'post_action',  'log', 'metrics',
    'ssl_certificate',
  }

  describe('.new', function()
    it('allows to set a name for the policy', function()
      local my_policy_name = 'custom_mapping_rules'
      local my_policy = policy.new(my_policy_name)

      assert.equals(my_policy_name, my_policy._NAME)
    end)

    it('allows to set a version for the policy', function()
      local my_policy_version = '2.0'
      local my_policy = policy.new('my_policy', my_policy_version)

      assert.equals(my_policy_version, my_policy._VERSION)
    end)

    it('set the version to 0.0 when not specified', function()
      local my_policy = policy.new('my_policy')
      assert.equals('0.0', my_policy._VERSION)
    end)

    it('defines a method for each of the nginx phases; they do nothing by default', function()
      local my_policy = policy.new('custom_authorizer')

      for _, phase in policy.phases() do
        -- To be precise, we should check that the function is defined, returns
        -- nil, and it does not have any side-effects. Checking the latter is
        -- complicated so we'll leave it for now.
        assert.not_nil(my_policy[phase])
        assert.is_nil(my_policy[phase]())
      end
    end)

    it('allows to set a custom function for each nginx phase', function()
      local my_policy = policy.new('custom_authorizer')
      my_policy.access = function() return 'custom_access_ran' end

      assert.equals('custom_access_ran', my_policy.access())
    end)
  end)

  describe('module equality', function()
    it('equals when name and version are the same', function()
      local p1 = policy.new('NAME', 'VERSION')
      local p2 = policy.new('NAME', 'VERSION')

      assert.are.equal(p1, p2)
      assert.not_same(p1, p2)
    end)

    it('is not equal when names are different', function()
      local p1 = policy.new('NAME', 'VERSION')
      local p2 = policy.new('NAME2', 'VERSION')

      assert.are.not_equal(p1, p2)
    end)

    it('is not equal when versions are different', function()
      local p1 = policy.new('NAME', 'VERSION')
      local p2 = policy.new('NAME', 'VERSION2')

      assert.are.not_equal(p1, p2)
    end)

    it('equals itself', function()
      local p = policy.new('NAME', 'VERSION')

      assert.are.equal(p, p)
      assert.are.same(p, p)
    end)
  end)

  describe('module tostring', function()
    it('shows name and version', function()
      local p1 = policy.new('NAME', 'VERSION')

      assert.equal('Policy: NAME (VERSION)', tostring(p1))
    end)
  end)

  describe('instance metatable', function()
    local p = policy.new('NAME', 'VERSION')

    it('has a policy property', function()
      local mt = getmetatable(p.new())
      assert.are.equal(mt.policy, p)
    end)
  end)

  describe('instance tostring', function()
    it('shows name and version', function()
      local p1 = policy.new('NAME', 'VERSION').new()

      assert.equal('Policy: NAME (VERSION)', tostring(p1))
    end)
  end)

  describe('.phases', function()
    it('returns the nginx phases where policies can run, sorted by order of execution', function()
      local res = {}
      for _, phase in policy.phases() do
        table.insert(res, phase)
      end

      assert.same(phases, res)
    end)
  end)

  describe('.request_phases', function()
    it('returns the request nginx phases where policies can run, sorted by order of execution', function()
      local request_phases = tab_clone(phases)
      table.remove(request_phases, 1) -- init
      table.remove(request_phases, 1) -- init_worker

      local res = {}
      for _, phase in policy.request_phases() do
        table.insert(res, phase)
      end

      assert.same(request_phases, res)
    end)
  end)

  describe('garbage collection', function()
    it('runs __gc metamethod when a policy instance is garbage-collected', function()
      local MyPolicy, mt = policy.new('my_policy', '1.0')
      local property
      mt.__gc = spy.new(function(instance) property = instance.someproperty end)
      local p = MyPolicy.new()
      p.someproperty = 'foobar'
      p = nil
      assert.is_nil(p)

      collectgarbage()

      assert.spy(mt.__gc).was_called(1)
      assert.equal('foobar', property)
    end)
  end)
end)
