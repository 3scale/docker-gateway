local policy = require('apicast.policy')
local _M = policy.new('Rate Limit Policy')

local resty_limit_conn = require('resty.limit.conn')
local resty_limit_req = require('resty.limit.req')
local resty_limit_count = require('resty.limit.count')

local ngx_semaphore = require "ngx.semaphore"
local limit_traffic = require "resty.limit.traffic"
local ts = require ('apicast.threescale_utils')
local tonumber = tonumber
local next = next
local shdict_key = 'limiter'

local insert = table.insert
local ipairs = ipairs
local unpack = table.unpack

local new = _M.new

local traffic_limiters = {
  connections = function(config)
    return resty_limit_conn.new(shdict_key, config.conn, config.burst, config.delay)
  end,
  leaky_bucket = function(config)
    return resty_limit_req.new(shdict_key, config.rate, config.burst)
  end,
  fixed_window = function(config)
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

local function redis_shdict(url)
  local options = { url = url }
  local redis, err = ts.connect_redis(options)
  if not redis then
    return nil, err
  end

  return {
    incr = function(_, key, value, init)
      if not init then
        return redis:incrby(key, value), nil
      end
      redis:setnx(key, init)
      return redis:incrby(key, value), nil
    end,
    set = function(_, key, value)
      return redis:set(key, value)
    end,
    expire = function(_, key, exptime)
      local ret = redis:expire(key, exptime)
      if ret == 0 then
        return nil, "not found"
      end
      return true, nil
    end,
    get = function(_, key)
      local val = redis:get(key)
      if type(val) == "userdata" then
        return nil
      end
      return val
    end
  }
end

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

local function build_limiters_and_keys(type, limiters, redis, error_settings)
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

    insert(res_limiters, lim)

    local key
    if limiter.key.scope == "service" then
      key = limiter.key.service_name.."_"..type.."_"..limiter.key.name
    else
      key = type.."_"..limiter.key.name
    end

    insert(res_keys, key)
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

  return self
end

function _M:access()
  local red
  if self.redis_url then
    local rederr
    red, rederr = redis_shdict(self.redis_url)
    if not red then
      ngx.log(ngx.ERR, "failed to connect Redis: ", rederr)
      error(self.error_settings, "configuration_issue")
      return
    end
  end

  local conn_limiters, conn_keys = build_limiters_and_keys(
    'connections', self.connection_limiters, red, self.error_settings)

  local leaky_bucket_limiters, leaky_bucket_keys = build_limiters_and_keys(
    'leaky_bucket', self.leaky_bucket_limiters, red, self.error_settings)

  local fixed_window_limiters, fixed_window_keys = build_limiters_and_keys(
    'fixed_window', self.fixed_window_limiters, red, self.error_settings)

  local limiters = {}
  insert(limiters, unpack(conn_limiters) or nil)
  insert(limiters, unpack(leaky_bucket_limiters) or nil)
  insert(limiters, unpack(fixed_window_limiters) or nil)

  local keys = {}
  insert(keys, unpack(conn_keys) or nil)
  insert(keys, unpack(leaky_bucket_keys) or nil)
  insert(keys, unpack(fixed_window_keys) or nil)

  local states = {}
  local connections_committed = {}
  local keys_committed = {}

  local delay, comerr = limit_traffic.combine(limiters, keys, states)
  if not delay then
    if comerr == "rejected" then
      ngx.log(ngx.WARN, "Requests over the limit.")
      error(self.error_settings, "limits_exceeded")
      return
    end
    ngx.log(ngx.ERR, "failed to limit traffic: ", comerr)
    error(self.error_settings, "configuration_issue")
    return
  end

  for i, lim in ipairs(limiters) do
    if lim.is_committed and lim:is_committed() then
      table.insert(connections_committed, lim)
      table.insert(keys_committed, keys[i])
    end
  end

  if next(connections_committed) ~= nil then
    local ctx = ngx.ctx
    ctx.limiters = connections_committed
    ctx.keys = keys_committed
  end

  if delay > 0 then
    ngx.log(ngx.WARN, 'need to delay by: ', delay, 's, states: ', table.concat(states, ", "))
    ngx.sleep(delay)
  end

end

local function checkin(_, ctx, time, semaphore, redis_url, error_settings)
  local limiters = ctx.limiters
  local keys = ctx.keys
  local latency = tonumber(time)

  local red
  if redis_url then
    local rederr
    red, rederr = redis_shdict(redis_url)
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
    semaphore:wait(10)
  end
end

return _M
