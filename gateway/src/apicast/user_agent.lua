local ffi = require 'ffi'
local env = require 'resty.env'

local setmetatable = setmetatable
local format = string.format

local _M = {
  _VERSION = require('apicast.version')
}

function _M.deployment()
  return _M.threescale_deployment_env or 'unknown'
end

-- User-Agent: <product> / <product-version> <comment>
-- User-Agent: Mozilla/<version> (<system-information>) <platform> (<platform-details>) <extensions>

function _M.call()
  return format('APIcast/%s (%s)', _M._VERSION, _M.system_information())
end

function _M.system_information()
  return ffi.os .. '; ' .. ffi.arch .. '; env:' .. _M.deployment()
end

local mt = {
  __call = _M.call,
  __tostring = _M.call
}

function _M.reset()
  local cache = {
    threescale_deployment_env = env.get('THREESCALE_DEPLOYMENT_ENV')
  }

  mt.__index = cache

  _M.env = cache

  mt.__call = _M.call
  mt.__tostring = _M.call
end

function _M.cache()
  _M.reset()

  local user_agent =  _M.call()

  mt.__call = function() return user_agent end
  mt.__tostring = mt.__call
end

setmetatable(_M, mt)

return _M
