local policy = require('apicast.policy')
local _M = policy.new('Rate Limiting to Service Policy')

local resty_limit_conn = require('resty.limit.conn')
local resty_limit_req = require('resty.limit.req')
local resty_limit_count = require('resty.limit.count')

local ngx_semaphore = require "ngx.semaphore"
local limit_traffic = require "resty.limit.traffic"
local ts = require ('apicast.threescale_utils')
local tonumber = tonumber
local next = next
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

local function init_limiter(config)
  return traffic_limiters[config.name](config)
end

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

local function try(f, catch_f)
  local status, exception = pcall(f)
  if not status then
    catch_f(exception)
  end
end

function _M.new(config)
  local self = new()
  self.config = config or {}
  self.redis_url = config.redis_url

  local limiters = {}
  local keys = {}

  if not self.redis_url then
    ngx.log(ngx.ERR, "No Redis information.")
    return ngx.exit(500)
  end

  for _, limiter in ipairs(config.limiters) do

    local lim, limerr
    local failed_to_instantiate = false
    try(
      function()
        lim, limerr = init_limiter(limiter)
        if not lim then
          ngx.log(ngx.ERR, "unknown limiter: ", limerr)
          failed_to_instantiate = true
        end
      end,
      function(e)
        ngx.log(ngx.ERR, "unknown limiter: ", e)
        failed_to_instantiate = true
      end
    )
    if failed_to_instantiate then
      return ngx.exit(500)
    end

    local rediserr
    lim.dict, rediserr = redis_shdict(self.redis_url)
    if not lim.dict then
      ngx.log(ngx.ERR, "failed to connect Redis: ", rediserr)
      return ngx.exit(500)
    end

    limiters[#limiters + 1] = lim
    keys[#keys + 1] = limiter.key

  end

  self.limiters = limiters
  self.keys = keys

  return self
end

function _M:access()
  local limiters = self.limiters
  local keys = self.keys
  local states = {}
  local connections_committed = {}
  local keys_committed = {}

  local delay, comerr = limit_traffic.combine(limiters, keys, states)
  if not delay then
    if comerr == "rejected" then
      ngx.log(ngx.ERR, "Requests over the limit.")
      return ngx.exit(429)
    end
    ngx.log(ngx.ERR, "failed to limit traffic: ", comerr)
    return ngx.exit(500)
  end

  for i, lim in ipairs(limiters) do
    if lim.iscommitted and lim:is_committed() then
      connections_committed[#connections_committed + 1] = lim
      keys_committed[#keys_committed + 1] = keys[i]
    end
  end

  if next(connections_committed) ~= nil then
    local ctx = ngx.ctx
    ctx.limiters = connections_committed
    ctx.keys = keys_committed
  end

  if delay >= 0.001 then
    ngx.log(ngx.WARN, 'need to delay by: ', delay, 's, states: ', table.concat(states, ", "))
    ngx.sleep(delay)
  end

end

local function checkin(_, ctx, time, semaphore, redis_url)
  local limiters = ctx.limiters
  local keys = ctx.keys

  for i, lim in ipairs(limiters) do
    local rediserr
    lim.dict, rediserr = redis_shdict(redis_url)
    if not lim.dict then
      ngx.log(ngx.ERR, "failed to connect Redis: ", rediserr)
      return ngx.exit(500)
    end

    local latency = tonumber(time)
    local conn, err = lim:leaving(keys[i], latency)
    if not conn then
      ngx.log(ngx.ERR, "failed to record the connection leaving request: ", err)
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
    ngx.timer.at(0, checkin, ngx.ctx, ngx.var.request_time, semaphore, self.redis_url)
    semaphore:wait(10)
  end
end

return _M
