-- This policy enables Web socket pass through on APIcast

local _M = require('apicast.policy').new('Websocket', 'builtin')

local new = _M.new

function _M.new(configuration)
  local policy = new(configuration)
  return policy
end

local function is_websocket_connection()
  local headers = ngx.req.get_headers()
  return headers["Upgrade"] ~= nil and headers["Sec-WebSocket-Key"] ~= nil
end

function _M:rewrite()
  if is_websocket_connection() then
    ngx.var.upstream_connection_header = "Upgrade"
  end
end

return _M
