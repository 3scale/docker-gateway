-- This policy enables HTTP2 handle on the API endpoint.

local policy = require('apicast.policy')
local _M = policy.new('grpc', "builtin")
local resty_url = require('resty.url')
local round_robin = require 'resty.balancer.round_robin'

local new = _M.new

local balancer = round_robin.new()

function _M.new(config)
  local self = new(config)
  return self
end

function _M:rewrite(context)
  if ngx.var.server_protocol == "HTTP/2.0" then
    -- upstream defined in gateway/conf.d/http2.conf
    context.upstream_location_name = "@grpc_upstream"
  end
end

function _M:balancer(context)
  if not context.upstream_location_name then
    return
  end

  -- balancer need to be used due to grpc_pass does not support variables and
  -- upstream block need to be in place.
  local upstream = context:get_upstream()
  if not upstream then
    ngx.log(ngx.WARN, "Upstream is not present in the balancer")
    return
  end

  local peers = balancer:peers(upstream.servers)
  local peer, err = balancer:select_peer(peers)
  if err then
    ngx.log(ngx.WARN, "Cannot get a peer for the given upstream", err)
    return
  end

  local ip = peer[1]
  local port = peer[2] or upstream.uri.port or resty_url.default_port(upstream.uri.scheme)
  local _, err = balancer:set_current_peer(ip, port)

  if err then
    ngx.log(ngx.WARN, "Cannot set balancer IP and port '", ip, ":", port, "'")
    return
  end
end

return _M
