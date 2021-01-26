local policy = require('apicast.policy')
local _M = policy.new('JWT check policy', 'builtin')

local Condition = require('apicast.conditions.condition')
local MappingRule = require('apicast.mapping_rule')
local Operation = require('apicast.conditions.operation')
local TemplateString = require('apicast.template_string')

local ipairs = ipairs

local new = _M.new

local default_error_message = "Request blocked due to JWT claim policy"
local default_template_type = 'plain'
local default_allowed_methods = { MappingRule.any_method }

local function deny_request(error_msg)
  ngx.status = ngx.HTTP_FORBIDDEN
  ngx.say(error_msg)
  ngx.exit(ngx.status)
end

function _M.new(config)
  local self = new(config)
  self.error_message = config.error_message or default_error_message
  self.rules = {}
  for _, rule in ipairs(config.rules) do
    local conditions = {}
    for _, condition in ipairs(rule.operations) do
      if condition.jwt_claim_type == "plain" then
        -- Due to this need to be fetched from the JWT claim, render  the match
        -- as liquid to be able to fetch the info from the JWT_claim
        condition.jwt_claim = "{{"..condition.jwt_claim.."}}"
      end

      table.insert( conditions,
        Operation.new(
          condition.jwt_claim, "liquid",
          condition.op,
          condition.value, condition.value_type or default_template_type))
    end
    table.insert( self.rules, {
      condition = Condition.new(conditions, rule.combine_op),
      methods = rule.methods or default_allowed_methods,
      resource = TemplateString.new(
        rule.resource,
        rule.resource_type or default_template_type),
    })
  end

  return self
end

-- is_rule_denied_request returns true if the request need to be blocked based
-- on a provided rule with the request context.
-- This function will only work if the request match on resource and in one of
-- the methods, the methods that are not  defined in the rule will be allowed.
local function is_rule_denied_request(rule, context)

  local uri = context:get_uri()
  local request_method =  ngx.req.get_method()

  local resource = rule.resource:render(context)
  local mapping_rule_match = false

  for _, method  in ipairs(rule.methods) do
    local mapping_rule = MappingRule.from_proxy_rule({
      http_method = method,
      pattern = resource,
      querystring_parameters = {},
      -- the name of the metric is irrelevant
      metric_system_name = 'hits'
    })
    if mapping_rule:matches(request_method, uri) then
      mapping_rule_match = true
      break
    end
  end

  if not mapping_rule_match then
    return false
  end

  return not rule.condition:evaluate(context.jwt)
end


function _M:access(context)
  for _, rule in ipairs(self.rules) do
    if is_rule_denied_request(rule, context) then
      return deny_request(self.error_message)
    end
  end
end

return _M
