local Executor = require 'apicast.executor'
local PolicyChain = require 'apicast.policy_chain'
local Policy = require 'apicast.policy'

describe('executor', function()
  local function policy_mt(policy)
    return getmetatable(policy).policy
  end

  it('forwards all the policy methods to the policy chain', function()
    local chain = PolicyChain.default()
    local exec = Executor.new(chain)
    -- Stub all the nginx phases methods for each of the policies
    for _, phase in Policy.phases() do
      for _, policy in ipairs(chain) do
        stub(policy, phase)
      end
    end

    -- For each one of the nginx phases, verify that when called on the
    -- executor, each one of the policies executes the code for that phase.
    for _, phase in Policy.phases() do
      exec[phase](exec)
      for _, policy in ipairs(chain) do
        assert.stub(policy[phase]).was_called(1)
      end
    end
  end)


  context('policy is in the chain', function()

    local executor
    local policy

    before_each(function()
      local chain = PolicyChain.build({'apicast.policy.apicast'})
      policy = getmetatable(chain[1]).__index
      executor = Executor.new(chain)
    end)

    it('calls .init just once', function()
      local init = stub(policy, 'init')

      executor:init()

      assert.stub(init).was_called(1)
    end)

    it('calls .init_worker just once', function()
      local init = stub(policy, 'init_worker')

      executor:init_worker()

      assert.stub(init).was_called(1)
    end)
  end)

  describe('when there are policies that are not in the chain', function()
    local policy_not_in_chain = {
      init = function() return '1' end,
      init_worker = function() return '2' end
    }

    before_each(function()
      stub(policy_not_in_chain, 'init')
      stub(policy_not_in_chain, 'init_worker')

      local policy_loader = require('apicast.policy_loader')
      stub(policy_loader, 'get_all').returns({ policy_not_in_chain })

      Executor.reset_available_policies()
    end)

    it('init() calls their init method', function()
      local executor = Executor.new(PolicyChain.default())

      executor:init()

      assert.stub(policy_not_in_chain.init).was_called(1)
    end)

    it('init_worker() calls their init_worker method', function()
      local executor = Executor.new(PolicyChain.default())

      executor:init_worker()

      assert.stub(policy_not_in_chain.init_worker).was_called(1)
    end)
  end)

  it('is initialized with default chain', function()
    local default = PolicyChain.default()
    local policy_chain = Executor.policy_chain

    assert.same(#default, #policy_chain)

    for i,policy in ipairs(default) do
      assert.same(policy._NAME, policy_chain[i]._NAME)
      assert.same(policy._VERSION, policy_chain[i]._VERSION)

      assert.equal(policy_mt(policy), policy_mt(policy_chain[i]))
    end
  end)

  it('freezes the policy chain', function()
    local chain = PolicyChain.new({})
    assert.falsy(chain.frozen)

    Executor.new(chain)
    assert.truthy(chain.frozen)
  end)

  describe('.context', function()
    it('returns what the policies of the chain export', function()
      local policy_1 = Policy.new('1')
      policy_1.export = function() return { p1 = '1'} end

      local policy_2 = Policy.new('2')
      policy_2.export = function() return { p2 = '2' } end

      local chain = PolicyChain.new({ policy_1, policy_2 })
      local context = Executor.new(chain):context('rewrite')

      assert.equal('1', context.p1)
      assert.equal('2', context.p2)
    end)

    it('works with policy chains that contain other chains', function()
      local policy_1 = Policy.new('1')
      policy_1.export = function() return { p1 = '1'} end

      local policy_2 = Policy.new('2')
      policy_2.export = function() return { p2 = '2' } end

      local policy_3 = Policy.new('3')
      policy_3.export = function() return { p3 = '3' } end

      local inner_chain = PolicyChain.new({ policy_2, policy_3 })
      local outer_chain = PolicyChain.new({ policy_1, inner_chain })

      local context = Executor.new(outer_chain):context('rewrite')

      assert.equal('1', context.p1)
      assert.equal('2', context.p2)
      assert.equal('3', context.p3)
    end)
  end)

  describe('.balancer', function()
    local chain
    local executor

    before_each(function()
      ngx.ctx.context = {}
      chain = PolicyChain.default()

      for _, policy in ipairs(chain) do
        stub(policy, 'balancer')
      end

      executor = Executor.new(chain)
    end)

    it('sets the balancer retries in the context', function()
      ngx.ctx.context = { balancer_retries = 2 }

      executor:balancer()

      assert.same(3, ngx.ctx.context.balancer_retries)
    end)

    it('sets a var in the context that marks that the peer has not been set yet in the current try', function()
      executor:balancer()

      assert.is_false(ngx.ctx.context.peer_set_in_current_balancer_try)
    end)

    it('forwards the call to the policy chain', function()
      executor:balancer()

      for _, policy in ipairs(chain) do
        assert.stub(policy.balancer).was_called(1)
      end
    end)
  end)
end)
