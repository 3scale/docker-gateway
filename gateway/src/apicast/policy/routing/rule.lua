local setmetatable = setmetatable
local ipairs = ipairs
local tab_insert = table.insert
local tab_new = require('resty.core.base').new_tab
local error = error

local Condition = require('apicast.conditions.condition')
local RoutingOperation = require('apicast.policy.routing.routing_operation')
local TemplateString = require 'apicast.template_string'
local Upstream = require('apicast.upstream')

local _M = {}

local mt = { __index = _M }

local function value_of_match(thing_to_be_matched, config_condition)
  return (thing_to_be_matched == 'header' and config_condition.header_name) or
    (thing_to_be_matched == 'query_arg' and config_condition.query_arg_name) or
    (thing_to_be_matched == 'jwt_claim' and config_condition.jwt_claim_name) or
    (thing_to_be_matched == 'liquid' and config_condition.liquid_value) or
    nil
end

local function init_operation(config_operation)
  local match = config_operation.match
  local match_val = value_of_match(match, config_operation)
  local op = config_operation.op
  local value = config_operation.value
  local value_type = config_operation.value_type

  if match == 'path' then
    return RoutingOperation.new_op_with_path(op, value, value_type)
  elseif match == 'header' then
    return RoutingOperation.new_op_with_header(match_val, op, value, value_type)
  elseif match == 'query_arg' then
    return RoutingOperation.new_op_with_query_arg(match_val, op, value, value_type)
  elseif match == 'jwt_claim' then
    return RoutingOperation.new_op_with_jwt_claim(match_val, op, value, value_type)
  elseif match == 'liquid' then
    return RoutingOperation.new_op_with_liquid_templating(match_val, op, value, value_type)
  else
    error('Thing to be matched not supported: ' .. match)
  end
end

local function init_condition(config_condition)
  local operations = tab_new(#config_condition.operations, 0)

  for _, operation in ipairs(config_condition.operations) do
    tab_insert(operations, init_operation(operation))
  end

  return Condition.new(operations, config_condition.combine_op)
end

-- config_rule is a rule as defined in the Routing policy
function _M.new_from_config_rule(config_rule)
  local self = setmetatable({}, mt)

  -- Validate the upstream to avoid creating invalid rules
  local upstream, err = Upstream.new(config_rule.url)

  if upstream then
    self.url = config_rule.url
    if config_rule.replace_path then
        self.replace_path =  TemplateString.new(config_rule.replace_path, "liquid")
    end

    self.host_header = config_rule.host_header
    self.condition = init_condition(config_rule.condition)
    self.owner_id = tonumber(config_rule.owner_id)
    return self
  else
    return nil, 'failed to initialize upstream from url: ',
                config_rule.url, ' err: ', err
  end
end

return _M
