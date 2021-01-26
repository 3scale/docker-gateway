--- Custom metrics policy

local _M  = require('apicast.policy').new('Custom Metrics', 'builtin')

local Condition = require('apicast.conditions.condition')
local LinkedList = require('apicast.linked_list')
local Operation = require('apicast.conditions.operation')
local ReportsBatch = require('apicast.policy.3scale_batcher.reports_batch')
local TemplateString = require('apicast.template_string')
local Usage = require('apicast.usage')
local backend_client = require('apicast.backend_client')
local deepcopy = require('pl.tablex').deepcopy
local http_ng_resty = require('resty.http_ng.backend.resty')

local ipairs = ipairs
local pairs = pairs
local str_len = string.len
local tinsert = table.insert

local default_combine_op = "and"
local default_template_type = "plain"
local liquid_template_type = "liquid"

local new = _M.new

local function get_context(context)

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
  ctx.jwt = context.jwt or {}
  return LinkedList.readonly(ctx, ngx.var)
end


local function load_condition(condition_config)
  if not condition_config then
    return nil
  end
  local operations = {}
  for _, operation in ipairs(condition_config.operations or {}) do
    tinsert( operations,
      Operation.new(
        operation.left,
        operation.left_type or default_template_type,
        operation.op,
        operation.right,
        operation.right_type or default_template_type))
  end

  return Condition.new(
    operations,
    condition_config.combine_op or default_combine_op)
end


local function load_rules(self, config_rules)
  if not config_rules then
    return
  end
  local rules = {}
  for _,rule in pairs(config_rules) do
      tinsert(rules, {
        condition = load_condition(rule.condition),
        metric = TemplateString.new(rule.metric or "", liquid_template_type),
        increment = TemplateString.new(rule.increment or "0", liquid_template_type)
      })
  end
  self.rules = rules
end


function _M.new(config)
  local self = new(config)

  self.rules = {}
  load_rules(self, config.rules or {})

  return self
end

-- report: Report the given usage information to the backend
function _M.report(context, usage)
  local backend = backend_client:new(context.service, http_ng_resty)
  local reports = {}
  for key, value in pairs(usage.deltas) do
    local result = deepcopy(context.credentials)
    result.metric = key
    result.value = value
    result.service_id = context.service.id
    tinsert(reports, result)
  end

  local res = backend:report(ReportsBatch.new(context.service.id, reports))
  if res.status ~= 200 then
    ngx.log(ngx.INFO, "Custom metric report usage failed")
  end
end

function _M:post_action(context)
  -- context with all variables are needed to retrieve information about API
  -- response
  local ctx = get_context(context)

  -- We initilize the usage, and if any rule match, we report the usage to
  -- backend.
  local match = false
  local usage = Usage.new()

  for _, rule in ipairs(self.rules) do
    if rule.condition:evaluate(ctx) then
      local metric = rule.metric:render(ctx)
      if str_len(metric) > 0 then
        usage:add(metric, tonumber(rule.increment:render(ctx)) or 0)
        match = true
      end
    end
  end

  if not match then
    return
  end

  -- If cached key authrep call will happen on APICast policy, so no need to
  -- report only one metric. If no cached key will report only the new metrics.
  if ngx.var.cached_key then
    context.usage:merge(usage)
    return
  end
  self.report(context, usage)
end

return _M
