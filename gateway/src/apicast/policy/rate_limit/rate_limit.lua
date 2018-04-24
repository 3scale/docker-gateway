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
local format = string.format
local insert = table.insert
local os_date = os.date
local os_time = os.time
local shdict_key = 'limiter'

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
    end,
    del = function(_, key)
      return redis:del(key)
    end
  }
end

local function error(error_settings, type)
  if error_settings[type]["error_handling"] == "exit" then
    return ngx.exit(error_settings[type]["status_code"])
  end
end

local function init_error_settings(config_error_settings)
  local error_settings = default_error_settings
  if config_error_settings then
    for _, error_setting in pairs(config_error_settings) do
      if error_setting.type then
        if error_setting.status_code then
          error_settings[error_setting.type]["status_code"] = error_setting.status_code
        end
        if error_setting.error_handling then
          error_settings[error_setting.type]["error_handling"] = error_setting.error_handling
        end
      end
    end
  end
  return error_settings
end

local function initialize_redis_records(redis, seed, limiters)
  for _, limiter in ipairs(limiters) do
    local key
    if limiter.key.scope == "service" then
      key = format("%s_%s_%s", limiter.key.service_name, limiter.name, limiter.key.name)
    else
      key = format("%s_%s", limiter.name, limiter.key.name)
    end

    local seed_key = format("%s_seed", key)
    local seed_value = redis:get(seed_key)

    if not seed_value or tonumber(seed_value) ~= seed then
      redis:set(seed_key, seed)

      if limiter.name == "connections" or limiter.name == "leaky_bucket" then
        redis:del(key)
      else
        local count_key = format("%s_count", key)
        local count = redis:get(count_key)

        local window_key = format("%s_window", key)
        local window = redis:get(window_key)

        if not count or not window or tonumber(count) ~= limiter.count or tonumber(window) ~= limiter.window then
          redis:del(key)
          redis:set(count_key, limiter.count)
          redis:set(window_key, limiter.window)
        end
      end
    end
  end
end

function _M.new(config)
  local self = new()
  self.config = config or {}
  self.limiters = config.limiters
  self.redis_url = config.redis_url
  self.error_settings = init_error_settings(config.error_settings)
  self.seed = os_time(os_date("!*t"))

  return self
end

function _M:access()
  local limiters = {}
  local keys = {}

  local red
  if self.redis_url then
    local rederr
    red, rederr = redis_shdict(self.redis_url)
    if not red then
      ngx.log(ngx.ERR, "failed to connect Redis: ", rederr)
      error(self.error_settings, "configuration_issue")
      return
    end

    initialize_redis_records(red, self.seed, self.limiters)
  end

  for _, limiter in ipairs(self.limiters) do
    local lim, initerr = traffic_limiters[limiter.name](limiter)
    if not lim then
      ngx.log(ngx.ERR, "unknown limiter: ", limiter.name, ", err: ", initerr)
      error(self.error_settings, "configuration_issue")
      return
    end

    lim.dict = red or lim.dict

    insert(limiters, lim)

    local key
    if limiter.key.scope == "service" then
      key = format("%s_%s_%s", limiter.key.service_name, limiter.name, limiter.key.name)
    else
      key = format("%s_%s", limiter.name, limiter.key.name)
    end

    insert(keys, key)

  end

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
