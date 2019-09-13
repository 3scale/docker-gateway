--- RoutingOperation
-- This module is based on the Operation one. The only difference is that
-- operations for the routing policy check request information that is not
-- available when the operation is instantiated, like headers, query arguments,
-- etc. That is the reason why in instances of this module, there are functions
-- to get the left operand instead of the operand itself.

local setmetatable = setmetatable
local Operation = require('apicast.conditions.operation')
local TemplateString = require('apicast.template_string')

local _M = {}

local mt = { __index = _M }

local function new(evaluate_left_side_func, op, value, value_type)
  local self = setmetatable({}, mt)

  self.evaluate_left_side_func = evaluate_left_side_func
  self.op = op
  self.value = value
  self.value_type = value_type

  return self
end

function _M.new_op_with_path(op, value, value_type)
  local eval_left_func = function(context) return context.request:get_uri() end
  return new(eval_left_func, op, value, value_type)
end

function _M.new_op_with_header(header_name, op, value, value_type)
  local eval_left_func = function(context)
    return context.request:get_header(header_name)
  end

  return new(eval_left_func, op, value, value_type)
end

function _M.new_op_with_query_arg(query_arg_name, op, value, value_type)
  local eval_left_func = function(context)
    return context.request:get_uri_arg(query_arg_name)
  end

  return new(eval_left_func, op, value, value_type)
end

function _M.new_op_with_jwt_claim(jwt_claim_name, op, value, value_type)
  local eval_left_func = function(context)
    local jwt = context.request:get_validated_jwt()
    return (jwt and jwt[jwt_claim_name]) or nil
  end

  return new(eval_left_func, op, value, value_type)
end

function _M.new_op_with_liquid_templating(liquid_expression, op, value, value_type)
  local eval_left_func = function(context)
    return TemplateString.new(liquid_expression or "" , "liquid"):render(context)
  end

  return new(eval_left_func, op, value, value_type)
end

function _M:evaluate(context)
  local left_operand_val = self.evaluate_left_side_func(context)

  local op = Operation.new(
    left_operand_val, 'plain', self.op, self.value, self.value_type
  )

  return op:evaluate(context)
end

return _M
