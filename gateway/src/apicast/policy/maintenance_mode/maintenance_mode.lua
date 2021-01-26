-- This policy allows to reject incoming requests with a
-- specified status code and message.
-- It's useful for maintenance periods or to temporarily block an API

local _M = require('apicast.policy').new('Maintenance mode', 'builtin')

local tonumber = tonumber
local new = _M.new

local default_status_code = 503
local default_message = "Service Unavailable - Maintenance"
local default_message_content_type = "text/plain; charset=utf-8"

local Condition = require('apicast.conditions.condition')
local Operation = require('apicast.conditions.operation')

function _M.new(configuration)
  local policy = new(configuration)

  policy.status_code = default_status_code
  policy.message = default_message
  policy.message_content_type = default_message_content_type

  if configuration then
    policy.status_code = tonumber(configuration.status) or policy.status_code
    policy.message = configuration.message or policy.message
    policy.message_content_type = configuration.message_content_type or policy.message_content_type
  end

  policy:load_condition(configuration)
  return policy
end

function _M:load_condition(config)
  if not config or not config.condition then
    return
  end

  local operations = {}
  for _, operation in ipairs(config.condition.operations or {}) do
    table.insert( operations,
      Operation.new(
        operation.left,
        operation.left_type or default_template_type,
        operation.op,
        operation.right,
        operation.right_type or default_template_type))
  end
  self.condition = Condition.new( operations, config.condition.combine_op or default_combine_op)
end

function set_maintenance_mode(self)
  ngx.header['Content-Type'] = self.message_content_type
  ngx.status = self.status_code
  ngx.say(self.message)

  return ngx.exit(ngx.status)
end

function _M:access(context)
  -- If no condition was configured, maintenance mode will be enabled by default
  if self.condition == nil then
    return set_maintenance_mode(self)
  end

  local upstream = context.route_upstream or context:get_upstream() or {}
  context.upstream = upstream.uri or upstream
  if self.condition:evaluate(context) then
    return set_maintenance_mode(self)
  end
end

return _M
