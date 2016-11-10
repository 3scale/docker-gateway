-- Apicast provides a plugin system. To add a custom plugin, we only need to
-- define a module that implements a few methods like rewrite(), access(), etc.
-- that are called in the appropriate nginx phases.
-- The goal of this lua module is to implement the methods that are not likely
-- to be changed from plugin to plugin so we do not have to repeated code
-- across all of them.

local balancer = require 'balancer'

-- Plugins need access to provider and configuration, so we need to expose them
local _M = { provider = require 'provider',
             configuration = require 'configuration' }

local missing_configuration = os.getenv('APICAST_MISSING_CONFIGURATION') or 'log'

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

local function init_provider()
  local config, err = _M.configuration.init()

  if config then
    _M.provider.init(config)
  else
    handle_missing_configuration(err)
  end
end

local function ensure_provider_is_initialized()
  -- load configuration if not configured
  -- that is useful when lua_code_cache is off
  -- because the module is reloaded and has to be configured again
  if not _M.provider.configured then
    local config = _M.configuration.boot()
    _M.provider.init(config)
  end
end

_M.init = init_provider
_M.init_worker = function() end
_M.rewrite = ensure_provider_is_initialized
_M.access = function() end
_M.balancer = balancer.call
_M.header_filter = function() end
_M.body_filter = function() end
_M.post_action = function() end

return _M
