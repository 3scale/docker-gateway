local configuration_store = require('apicast.configuration_store')
local configuration_parser = require 'apicast.configuration_parser'
local mock_loader = require 'apicast.configuration_loader.mock'
local file_loader = require 'apicast.configuration_loader.file'
local data_url_loader = require 'apicast.configuration_loader.data_url'
local remote_loader_v1 = require 'apicast.configuration_loader.remote_v1'
local remote_loader_v2 = require 'apicast.configuration_loader.remote_v2'
local oidc_loader = require 'apicast.configuration_loader.oidc'
local util = require 'apicast.util'
local env = require('resty.env')
local resty_url = require('resty.url')
local synchronization = require('resty.synchronization').new(1)

local error = error
local len = string.len
local format = string.format
local assert = assert
local pcall = pcall
local tonumber = tonumber

local lazy_load_timeout = 15

local noop = function(...) return ... end

local _M = {
  _VERSION = '0.1'
}

function _M.load(host)
  local configuration = env.get('APICAST_CONFIGURATION')
  local uri = resty_url.parse(configuration, [[\w+]])

  if uri then
    local scheme = uri.scheme

    if scheme == 'file' then
      env.set('THREESCALE_CONFIG_FILE', uri.opaque or uri.path)
    elseif scheme == 'http' or scheme == 'https' then
      env.set('THREESCALE_PORTAL_ENDPOINT', uri)
    elseif scheme == 'data' then -- TODO: this requires upgrading lua-resty-env
      return data_url_loader.call(configuration)
    else
      ngx.log(ngx.WARN, 'unknown configuration URI: ', uri)
    end
  elseif configuration then
    do -- TODO: this will be not necessary upgrading lua-resty-env
      local config = data_url_loader.call(configuration)

      if config then return config end
    end

    ngx.log(ngx.DEBUG, 'falling back to file system path for configuration')
    env.set('THREESCALE_CONFIG_FILE', configuration)
  end

  return oidc_loader.call(mock_loader.call() or file_loader.call() or remote_loader_v2:call(host) or remote_loader_v1.call(host))
end

function _M.boot(host)
  return _M.load(host) or error('missing configuration')
end

_M.mock = mock_loader.save

local function ttl()
  return tonumber(env.value('APICAST_CONFIGURATION_CACHE') or 0, 10)
end

function _M.global(contents)
  local context = require('apicast.executor'):context()

  return _M.configure(context.configuration, contents)
end

function _M.configure(configuration, contents)
  if not configuration then
    return nil, 'not initialized'
  end

  local config, err = configuration_parser.parse(contents)

  if err then
    ngx.log(ngx.WARN, 'not configured: ', err)
    ngx.log(ngx.DEBUG, 'config: ', contents)

    return nil, err
  end

  if config then
    configuration:store(config, ttl())
    collectgarbage()
    return config
  end
end

function _M.configured(configuration, host)
  if not configuration or not configuration.find_by_host then return nil, 'not initialized' end

  local hosts = configuration:find_by_host(host, false)

  return #hosts > 0
end

-- Cosocket API is not available in the init_by_lua* context (see more here: https://github.com/openresty/lua-nginx-module#cosockets-not-available-everywhere)
-- For this reason a new process needs to be started to download the configuration through 3scale API
function _M.run_external_command(cmd, cwd)
  local config, err, code = util.system(format('cd %s && %s/libexec/%s',
    cwd or  '.',
    env.get('APICAST_DIR') or env.get('TEST_NGINX_APICAST_PATH') or '.',
    cmd or 'boot'))

  -- Try to read the file in current working directory before changing to the prefix.
  if err then config = file_loader.call() end

  if config and len(config) > 0 then
    return config
  elseif err then
    if code then
      return nil, err, code
    else
      ngx.log(ngx.ERR, 'failed to read output from command ', cmd, ' err: ', err)
      return nil, err
    end
  end
end

local boot = {
  rewrite = noop,
  ttl = function() return tonumber(env.value('APICAST_CONFIGURATION_CACHE'), 10) end
}

function boot.init(configuration)
  local config, err, code = _M.run_external_command('boot')
  local init = _M.configure(configuration, config)

  if config and init then
    ngx.log(ngx.DEBUG, 'downloaded configuration: ', config)
  else
    ngx.log(ngx.EMERG, 'failed to load configuration, exiting (code ', code, ')\n',  err or ngx.config.debug and debug.traceback())
    os.exit(1)
  end

  if boot.ttl() == 0 then
    ngx.log(ngx.EMERG, 'cache is off, cannot store configuration, exiting')
    os.exit(0)
  end
end

local function refresh_configuration(configuration)
  local config = _M.load()
  local init, err = _M.configure(configuration, config)

  if init then
    ngx.log(ngx.DEBUG, 'updated configuration via timer: ', config)
  else
    ngx.log(ngx.EMERG, 'failed to update configuration: ', err)
  end
end

function boot.init_worker(configuration)
  local interval = boot.ttl() or 0

  local function schedule(...)
    local ok, err = ngx.timer.at(...)

    if not ok then
      ngx.log(ngx.ERR, "failed to create the auto update timer: ", err)
      return
    end
  end

  local handler

  handler = function (premature, ...)
    if premature then return end

    ngx.log(ngx.INFO, 'auto updating configuration')

    local updated, err = pcall(refresh_configuration, ...)

    if updated then
      ngx.log(ngx.INFO, 'auto updating configuration finished successfuly')
    else
      ngx.log(ngx.ERR, 'auto updating configuration failed with: ', err)
    end

    schedule(interval, handler, ...)
  end

  if interval > 0 then
    schedule(interval, handler, configuration)
  end
end

local lazy = { init_worker = noop }

function lazy.init(configuration)
  configuration.configured = true
end

local function lazy_load_config(configuration, host)
    local config = _M.load(host)
    if not config then
      ngx.log(ngx.WARN, 'failed to get config for host: ', host)
    end
    _M.configure(configuration, config)
end

function lazy.rewrite(configuration, host)
  if not host then
    return nil, 'missing host'
  end

  if ttl() == 0 then
    configuration = configuration_store.new(configuration.cache_size)
  end

  if _M.configured(configuration, host) then
    return configuration
  end

  local ret, result = synchronization:run(host, lazy_load_timeout, lazy_load_config, configuration, host)
  if not ret then
    ngx.log(ngx.WARN, 'failed to load config for host: ', host, ' error: ', result)
  end

  return configuration
end

local test = { init = noop, init_worker = noop, rewrite = noop }

local modes = {
  boot = boot, lazy = lazy, default = 'lazy', test = test
}

function _M.new(mode)
  mode = mode or env.value('APICAST_CONFIGURATION_LOADER') or modes.default
  local loader = modes[mode]
  ngx.log(ngx.INFO, 'using ', mode, ' configuration loader')
  return assert(loader, 'invalid config loader mode')
end

return _M
