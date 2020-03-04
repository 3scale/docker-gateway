local configuration_store = require 'apicast.configuration_store'
local host_based_finder = require('apicast.policy.find_service.host_based_finder')
local path_based_finder = require('apicast.policy.find_service.path_based_finder')

local Policy = require('apicast.policy')
local _M = Policy.new('Find Service Policy')

local new = _M.new

local function path_based_with_fallback_to_host(configuration, host)
  return path_based_finder.find_service(configuration, host) or
         host_based_finder.find_service(configuration, host)
end

local function find_service_func(path_routing_enabled, path_routing_only)
  if path_routing_only then
    ngx.log(ngx.DEBUG, 'Using path-based routing')
    return path_based_finder.find_service
  elseif path_routing_enabled then
    ngx.log(ngx.DEBUG, 'Using path-based routing with fallback to host-based routing')
    return path_based_with_fallback_to_host
  else
    ngx.log(ngx.DEBUG, 'Using host-based routing')
    return host_based_finder.find_service
  end
end

function _M.new(...)
  local self = new(...)

  self.find_service = find_service_func(
    configuration_store.path_routing,
    configuration_store.path_routing_only
  )

  return self
end

local function find_service(policy, context)
  context.service = context.service or policy.find_service(context.configuration, context.host)

  if context.service then
    ngx.log(ngx.DEBUG, "Using service id=", context.service.id)
  else
    ngx.log(ngx.DEBUG, 'Could not find a service for the request')
  end

end

_M.rewrite = find_service

-- ssl_certificate is the first phase executed when request arrives on HTTPS
-- therefore it needs to find a service to build a policy chain.
-- The method and the path are not available in the ssl_certificate phase, so
-- path-based routing does not work. It should always find the service by host.
function _M:ssl_certificate(context)
  if self.find_service ~= host_based_finder.find_service then
    ngx.log(ngx.WARN, 'Configured to do path-based routing, but it is not',
                      'compatible with TLS. Falling back to routing by host.')
  end

  context.service = context.service or
                    host_based_finder.find_service(context.configuration, context.host)
end

return _M
