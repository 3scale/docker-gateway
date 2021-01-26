local policy = require('apicast.policy')
local _M = policy.new('Rate Limit Policy')

local resty_limit_conn = require('resty.limit.conn')
local resty_limit_req = require('resty.limit.req')
local resty_limit_count = require('resty.limit.count-inc')

local ngx_semaphore = require "ngx.semaphore"
local limit_traffic = require "resty.limit.traffic"
local redis_shdict = require('redis_shdict')

local Condition = require('apicast.conditions.condition')
local Operation = require('apicast.conditions.operation')

local tonumber = tonumber
local next = next
local shdict_key = 'limiter'

local insert = table.insert
local ipairs = ipairs
local format = string.format
local concat = table.concat

local TemplateString = require 'apicast.template_string'
local default_name_type = 'plain'

local new = _M.new

local traffic_limiters = {
  connections = function(config)
    return resty_limit_conn.new(shdict_key, config.conn, config.burst, config.delay)
  end,
  leaky_bucket = function(config)
    return resty_limit_req.new(shdict_key, config.rate, config.burst)
  end,
  fixed_window = function(config)
    if not config.window or config.window <= 0 then
        config.window = 1
    end
    return resty_limit_count.new(shdict_key, config.count, config.window)
  end
}

local default_error_settings = {
  limits_exceeded = {
    status_code = 429,
    error_handling = "exit"
  },
  configuration_issue = {
    status_code = 500,
    error_handling = "exit"
  }
}

local function error(error_settings, type)
  if error_settings[type]["error_handling"] == "exit" then
    return ngx.exit(error_settings[type]["status_code"])
  end
end

local function init_error_settings(limits_exceeded_error, configuration_error)
  local error_settings = default_error_settings

  if limits_exceeded_error then
    if limits_exceeded_error.status_code then
      error_settings.limits_exceeded.status_code = limits_exceeded_error.status_code
    end

    if limits_exceeded_error.error_handling then
      error_settings.limits_exceeded.error_handling = limits_exceeded_error.error_handling
    end
  end

  if configuration_error then
    if configuration_error.status_code then
      error_settings.configuration_issue.status_code = configuration_error.status_code
    end

    if configuration_error.error_handling then
      error_settings.configuration_issue.error_handling = configuration_error.error_handling
    end
  end

  return error_settings
end

local function build_operations(config_ops)
  local res = {}

  for _, op in ipairs(config_ops or {}) do
    insert(res, Operation.new(op.left, op.left_type, op.op, op.right, op.right_type))
  end

  return res
end

local function build_condition(config_condition)
  local cond = config_condition or {}

  return Condition.new(
    build_operations(cond.operations or {}),
    cond.combine_op
  )
end

local function build_limiters_and_keys(type, limiters, redis, error_settings, context)
  local res_limiters = {}
  local res_keys = {}

  for _, limiter in ipairs(limiters) do
    local lim, initerr = traffic_limiters[type](limiter)

    if not lim then
      ngx.log(ngx.ERR, "unknown limiter: ", type, ", err: ", initerr)
      error(error_settings, "configuration_issue")
      return
    end

    lim.dict = redis or lim.dict

    lim.condition_is_true = function(context)
      local condition = build_condition(limiter.condition)
      return condition:evaluate(context)
    end

    insert(res_limiters, lim)

    local key = limiter.template_string:render(context)
    if limiter.key.scope == "global" then
      key = format("%s_%s", type, key)
    else
      key = format("%s_%s_%s", context.service.id, type, key)
    end
    if type == "fixed_window" then
      local time = ngx.time()
      local window = limiter.window
      key = format("%d_%s", time - (time % window), key)
    end

    insert(res_keys, key)
  end

  return res_limiters, res_keys
end

local function build_templates(limiters)
  for _, limiter in ipairs(limiters) do
    limiter.template_string = TemplateString.new(
      limiter.key.name, limiter.key.name_type or default_name_type)
  end
end

local function select_condition_is_true(groups_of_limiters, groups_of_keys, policies_ctx)
  local res_limiters = {}
  local res_keys = {}

  for i = 1, #groups_of_limiters do
    local limiters = groups_of_limiters[i]
    local keys = groups_of_keys[i]

    for j = 1, #limiters do
      local limiter = limiters[j]
      local key = keys[j]

      if limiter.condition_is_true(policies_ctx) then
        insert(res_limiters, limiter)
        insert(res_keys, key)
      end
    end
  end

  return res_limiters, res_keys
end

function _M.new(config)
  local self = new()
  self.config = config or {}
  self.connection_limiters = config.connection_limiters or {}
  self.leaky_bucket_limiters = config.leaky_bucket_limiters or {}
  self.fixed_window_limiters = config.fixed_window_limiters or {}
  self.redis_url = config.redis_url
  self.error_settings = init_error_settings(
    config.limits_exceeded_error, config.configuration_error)

  for _, limiters in ipairs({ self.connection_limiters, self.leaky_bucket_limiters, self.fixed_window_limiters }) do
    build_templates(limiters)
  end

  return self
end

function _M:access(context)
  local red
  if self.redis_url and self.redis_url ~= '' then
    local rederr
    red, rederr = redis_shdict.new{ url = self.redis_url }
    if not red then
      ngx.log(ngx.ERR, "failed to connect Redis: ", rederr)
      error(self.error_settings, "configuration_issue")
      return nil, rederr
    end
  end

  local conn_limiters, conn_keys = build_limiters_and_keys(
    'connections', self.connection_limiters, red, self.error_settings, context)

  local leaky_bucket_limiters, leaky_bucket_keys = build_limiters_and_keys(
    'leaky_bucket', self.leaky_bucket_limiters, red, self.error_settings, context)

  local fixed_window_limiters, fixed_window_keys = build_limiters_and_keys(
    'fixed_window', self.fixed_window_limiters, red, self.error_settings, context)

  local limiter_groups = { conn_limiters, leaky_bucket_limiters, fixed_window_limiters }
  local keys_groups = { conn_keys, leaky_bucket_keys, fixed_window_keys }
  local limiters, keys = select_condition_is_true(limiter_groups, keys_groups, context)

  local states = {}
  local connections_committed = {}
  local keys_committed = {}

  local delay, comerr = limit_traffic.combine(limiters, keys, states)
  if not delay then
    if comerr == "rejected" then
      ngx.log(ngx.WARN, "Requests over the limit.")
      error(self.error_settings, "limits_exceeded")
      return nil, 'limits exceeded'
    else
      ngx.log(ngx.ERR, "failed to limit traffic: ", comerr)
      error(self.error_settings, "configuration_issue")
      return nil, comerr or 'invalid configuration'
    end
  end

  for i, lim in ipairs(limiters) do
    if lim.is_committed and lim:is_committed() then
      insert(connections_committed, lim)
      insert(keys_committed, keys[i])
    end
  end

  if next(connections_committed) ~= nil then
    local ctx = ngx.ctx
    ctx.limiters = connections_committed
    ctx.keys = keys_committed
  end

  if delay > 0 then
    ngx.log(ngx.WARN, 'need to delay by: ', delay, 's, states: ', concat(states, ", "))
    ngx.sleep(delay)
  end

  return true, delay
end

local function checkin(_, ctx, time, semaphore, redis_url, error_settings)
  local limiters = ctx.limiters
  local keys = ctx.keys
  local latency = tonumber(time)

  local red
  if redis_url and redis_url ~= '' then
    local rederr
    red, rederr = redis_shdict.new{ url = redis_url }
    if not red then
      ngx.log(ngx.ERR, "failed to connect Redis: ", rederr)
      error(error_settings, "configuration_issue")
      return
    end
  end

  for i, lim in ipairs(limiters) do
    lim.dict = red or lim.dict

    local conn, err = lim:leaving(keys[i], latency)
    if not conn then
      ngx.log(ngx.ERR, "failed to record the connection leaving request: ", err)
      error(error_settings, "configuration_issue")
      return
    end
  end

  if semaphore then
    semaphore:post(1)
  end

end

function _M:log()
  local ctx = ngx.ctx
  local limiters = ctx.limiters
  if limiters and next(limiters) ~= nil then
    local semaphore = ngx_semaphore.new()
    ngx.timer.at(0, checkin, ngx.ctx, ngx.var.request_time, semaphore, self.redis_url, self.error_settings)
    return semaphore:wait(10)
  end
end

return _M
