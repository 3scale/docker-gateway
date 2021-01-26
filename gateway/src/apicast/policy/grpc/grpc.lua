-- This policy enables HTTP2 handle on the API endpoint.

local policy = require('apicast.policy')
local _M = policy.new('grpc', "builtin")

local apicast_balancer = require('apicast.balancer')
local new = _M.new

function _M.new(config)
  local self = new(config)
  return self
end

function _M:rewrite(context)
    -- upstream defined in gateway/conf.d/http2.conf
    context.upstream_location_name = "@grpc_upstream"
    ngx.var.proxy_host = "upstream"
end

_M.balancer = apicast_balancer.call

return _M
