local setmetatable = setmetatable
local ipairs = ipairs
local tab_insert = table.insert
local tab_new = require('resty.core.base').new_tab

local Condition = require('apicast.conditions.condition')
local Operation = require('apicast.conditions.operation')

local _M = {}

local mt = { __index = _M }

local function init_operation(config_operation)
  local left = config_operation.left
  local left_type = config_operation.left_type or "plain"
  local op = config_operation.op
  local right = config_operation.right
  local right_type = config_operation.right_type
  return Operation.new(left, left_type, op, right, right_type)
end

local function init_condition(config_condition)
  local operations = tab_new(#config_condition.operations, 0)

  for _, operation in ipairs(config_condition.operations) do
    tab_insert(operations, init_operation(operation))
  end

  return Condition.new(operations, config_condition.combine_op or "and")
end


function _M.new_from_config_rule(config_rule)
  local self = setmetatable({}, mt)

  self.cache = config_rule.cache or false
  self.header = config_rule.header or nil
  self.condition = init_condition(config_rule.condition)
  return self
end

return _M
