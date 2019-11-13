--- Logging policy

local _M  = require('apicast.policy').new('Logging Policy', 'builtin')
local new = _M.new

local Condition = require('apicast.conditions.condition')
local LinkedList = require('apicast.linked_list')
local Operation = require('apicast.conditions.operation')
local TemplateString = require('apicast.template_string')
local cjson = require('cjson')

local ipairs = ipairs

-- Defined in ngx.conf.liquid and used in the 'access_logs' directive.
local ngx_var_access_logs_enabled = 'access_logs_enabled'
local ngx_var_extended_access_logs_enabled = 'extended_access_logs_enabled'
local ngx_var_extended_access_log = 'extended_access_log'

local default_enable_access_logs = true
local default_template_type = 'plain'
local default_combine_op = "and"

-- Returns the value for the ngx var above from a boolean that indicates
-- whether access logs are enabled or not.
local val_for_ngx_var ={
  [true] = '1',
  [false] = '0'
}

function _M.new(config)
  local self = new(config)

  local enable_access_logs = config.enable_access_logs
  if enable_access_logs == nil then -- Avoid overriding when it's false.
    enable_access_logs = default_enable_access_logs
  end

  if not enable_access_logs then
    ngx.log(ngx.DEBUG, 'Disabling access logs')
  end

  self.enable_access_logs_val = val_for_ngx_var[enable_access_logs]
  self.custom_logging = config.custom_logging
  self.enable_json_logs = config.enable_json_logs
  self.json_object_config = config.json_object_config or {}

  self:load_condition(config)

  return self
end

function _M:load_condition(config)
  if not config.condition then
    return
  end

  ngx.log(ngx.DEBUG, 'Enabling extended log with conditions')
  local operations = {}
  for _, operation in ipairs(config.condition.operations) do
    table.insert( operations,
      Operation.new(
        operation.match, operation.match_type,
        operation.op,
        operation.value, operation.value_type or default_template_type))
  end
  self.condition = Condition.new( operations, config.condition.combine_op or default_combine_op)
end

local function get_request_context(context)
  local ctx = { }
  ctx.req = {
    headers=ngx.req.get_headers(),
  }

  ctx.resp = {
    headers=ngx.resp.get_headers(),
  }

  ctx.usage = context.usage
  ctx.service = context.service or {}
  ctx.original_request = context.original_request
  return LinkedList.readonly(ctx, ngx.var)
end

local function enable_extended_access_log()
  ngx.var[ngx_var_extended_access_logs_enabled] = 1
end

local function disable_extended_access_log()
  ngx.var[ngx_var_extended_access_logs_enabled] = 0
end

local function disable_default_access_logs()
  ngx.var[ngx_var_access_logs_enabled] = 0
end

--- log_dump_json: returns an string with the json output.
local function log_dump_json(self, extended_context)
  local result = {}
  for _, value in ipairs(self.json_object_config) do
    result[value.key] = TemplateString.new(value.value, value.value_type or default_template_type):render(extended_context)
  end

  local status, data = pcall(cjson.encode, result)
  if not status then
    ngx.log(ngx.WARN, "cannot serialize json on logging, err:", data)
    -- Disable access log due to no valid information can be returned
    disable_extended_access_log()
    return ""
  end

  return data
end

-- log_dump_line: render the liquid custom_logging value and return it.
local function log_dump_line(self, extended_context)
  local tmpl = TemplateString.new(self.custom_logging, "liquid")
  return tmpl:render(extended_context)
end

-- get_log_line return the log line based on the kind of log defined in the
-- service, if Json is enabled will dump a json object, if not will render the
-- simple log line.
function _M:get_log_line(extended_context)
  if self.enable_json_logs then
    return log_dump_json(self, extended_context)
  end
  return log_dump_line(self, extended_context)
end


function _M:use_default_access_logs()
  return not (self.custom_logging or self.enable_json_logs)
end

function _M:log(context)
  ngx.var[ngx_var_access_logs_enabled] = self.enable_access_logs_val
  if self:use_default_access_logs() then
    return
  end
  -- Extended log is now enaled, disable the default access_log
  disable_default_access_logs()

  local extended_context = get_request_context(context or {})
  if self.condition and not self.condition:evaluate(extended_context) then
    -- Access log is disabled here, request does not match, so log is disabled
    -- for this request
    disable_extended_access_log()
    return
  end

  enable_extended_access_log()
  ngx.var[ngx_var_extended_access_log] = self:get_log_line(extended_context)
end

return _M
