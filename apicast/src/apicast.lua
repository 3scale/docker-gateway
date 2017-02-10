local proxy = require('proxy')
local balancer = require('balancer')
local configuration_loader = require('configuration_loader')
local pcall = pcall
local tonumber = tonumber
local math = math
local setmetatable = setmetatable
local env = require('resty.env')
local reload_config = env.enabled('APICAST_RELOAD_CONFIG')
local user_agent = require('user_agent')
local newrelic_agent = require('resty.newrelic_agent')

local noop = function() end

local _M = {
  _VERSION = '3.0.0-pre',
  _NAME = 'APIcast'
}

local missing_configuration = env.get('APICAST_MISSING_CONFIGURATION') or 'log'
local request_logs = env.enabled('APICAST_REQUEST_LOGS')

local function handle_missing_configuration(err)
  if missing_configuration == 'log' then
    ngx.log(ngx.ERR, 'failed to load configuration, continuing: ', err)
  elseif missing_configuration == 'exit' then
    ngx.log(ngx.EMERG, 'failed to load configuration, exiting: ', err)
    os.exit(1)
  else
    ngx.log(ngx.ERR, 'unknown value of APICAST_MISSING_CONFIGURATION: ', missing_configuration)
    os.exit(1)
  end
end

local mt = {
  __index = _M
}
function _M.new()
  return setmetatable({ proxy = proxy.new() }, mt)
end

function _M.init()
  user_agent.cache()

  math.randomseed(ngx.now())
  -- First calls to math.random after a randomseed tend to be similar; discard them
  for _=1,3 do math.random() end

  local config, err = configuration_loader.init()
  local init = config and proxy.init(config)

  if not init then
    handle_missing_configuration(err)
  end
end

local function refresh_config()
  local config, err = configuration_loader.boot()

  if config then
    proxy.init(config)
  else
    ngx.log(ngx.ERR, 'failed to refresh configuration: ', err)
  end
end

function _M.init_worker()
  newrelic_agent.enable()

  local interval = tonumber(env.get('AUTO_UPDATE_INTERVAL'), 10) or 0

  local function schedule(...)
    local ok, err = ngx.timer.at(...)

    if not ok then
      ngx.log(ngx.ERR, "failed to create the auto update timer: ", err)
      return
    end
  end

  local handler

  handler = function (premature)
    if premature then return end

    ngx.log(ngx.INFO, 'auto updating configuration')

    local updated, err = pcall(refresh_config)

    if updated then
      ngx.log(ngx.INFO, 'auto updating configuration finished successfuly')
    else
      ngx.log(ngx.ERR, 'auto updating configuration failed with: ', err)
    end

    schedule(interval, handler)
  end

  if interval > 0 then
    schedule(interval, handler)
  end
end

function _M:rewrite()
  newrelic_agent.start_web_transaction()
  ngx.var.nr_transaction_id = ngx.ctx.nr_transaction_id

  local host = ngx.var.host
  local p = self.proxy
  -- load configuration if not configured
  -- that is useful when lua_code_cache is off
  -- because the module is reloaded and has to be configured again
  if not p:configured(host) or reload_config then
    local config = configuration_loader.boot(host)
    p:configure(config)
  end

  p.set_upstream(p.set_service(host))
end

function _M.post_action()
  proxy:post_action()
end

function _M:access()
  local p = self.proxy
  local fun = p:call() -- proxy:access() or oauth handler
  return fun()
end

if request_logs then
  ngx.log(ngx.WARN, 'ENABLED REQUEST LOGS')

  function _M.body_filter()
    ngx.ctx.buffered = (ngx.ctx.buffered or "") .. string.sub(ngx.arg[1], 1, 1000)

    if ngx.arg[2] then
      ngx.var.resp_body = ngx.ctx.buffered
    end
  end

  function _M.header_filter()

    ngx.var.resp_headers = require('cjson').encode(ngx.resp.get_headers())
  end
else
  _M.body_filter = noop
  _M.header_filter = noop
end

_M.balancer = balancer.call

_M.log = function()
  ngx.ctx.nr_transaction_id = ngx.var.nr_transaction_id
  newrelic_agent.finish_web_transaction()
end

return _M
