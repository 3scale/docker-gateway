local mock_loader = require 'configuration_loader.mock'
local file_loader = require 'configuration_loader.file'
local remote_loader_v1 = require 'configuration_loader.remote_v1'
local util = require 'util'
local hawkular = require 'resty.hawkular'

local tostring = tostring
local error = error
local len = string.len

local _M = {
  _VERSION = '0.1'
}

_M.boot = hawkular.wrap('configuration', function(host)
  return mock_loader.call() or file_loader.call() or remote_loader_v1.call(host) or error('missing configuration')
end)

_M.save = mock_loader.save

-- Cosocket API is not available in the init_by_lua* context (see more here: https://github.com/openresty/lua-nginx-module#cosockets-not-available-everywhere)
-- For this reason a new process needs to be started to download the configuration through 3scale API
function _M.init(cwd)
  cwd = cwd or ngx.config.prefix()
  local config, err, code = util.system("cd '" .. cwd .."' && libexec/boot")

  -- Try to read the file in current working directory before changing to the prefix.
  if err then config = file_loader.call() end

  if config and len(config) > 0 then
    return config
  elseif err then
    if code then
      ngx.log(ngx.ERR, 'boot could not get configuration, ' .. tostring(err) .. ': '.. tostring(code))
      return nil, err
    else
      ngx.log(ngx.ERR, 'boot failed read: '.. tostring(err))
      return nil, err
    end
  end
end

return _M
