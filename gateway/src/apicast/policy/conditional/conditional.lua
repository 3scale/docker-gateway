local ipairs = ipairs
local insert = table.insert

local policy = require('apicast.policy')
local policy_phases = require('apicast.policy').phases
local PolicyChain = require('apicast.policy_chain')
local Condition = require('apicast.conditions.condition')
local Operation = require('apicast.conditions.operation')
local ngx_variable = require('apicast.policy.ngx_variable')

local _M = policy.new('Conditional policy', 'builtin')

local new = _M.new

local function build_policy_chain(chain)
  if not chain then return {} end

  local policies = {}

  for i=1, #chain do
    policies[i] = PolicyChain.load_policy(
      chain[i].name,
      chain[i].version,
      chain[i].configuration
    )
  end

  return PolicyChain.new(policies)
end

local function build_operations(config_ops)
  local res = {}

  for _, op in ipairs(config_ops) do
    insert(res, Operation.new(op.left, op.left_type, op.op, op.right, op.right_type))
  end

  return res
end

function _M.new(config)
  local self = new(config)

  config.condition = config.condition or {}
  self.condition = Condition.new(
    build_operations(config.condition.operations),
    config.condition.combine_op
  )

  self.policy_chain = build_policy_chain(config.policy_chain)
  return self
end

function _M:export()
  return self.policy_chain:export()
end

-- Forward policy phases to chain
for _, phase in policy_phases() do
  _M[phase] = function(self, context)
    local condition_is_true = self.condition:evaluate(
      ngx_variable.available_context(context)
    )

    if condition_is_true then
      ngx.log(ngx.DEBUG, 'Condition met in conditional policy')
      self.policy_chain[phase](self.policy_chain, context)
    else
      ngx.log(ngx.DEBUG, 'Condition not met in conditional policy')
    end
  end
end

-- To avoid calling init and init_worker more than once in the policies
_M.init = function() end
_M.init_worker = function() end

return _M
