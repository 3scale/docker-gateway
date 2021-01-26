local _M  = require('apicast.policy').new('Payload size policy', 'builtin')
local new = _M.new

local ngx_exit = ngx.exit
local ngx_say = ngx.say

function _M.new(config)
  local self = new(config)
  self.request_limit = tonumber(config.request) or 0
  self.response_limit = tonumber(config.response) or 0
  return self
end

function _M:access()
  if self.request_limit <= 0 then
    return
  end

  -- No content-length header is present
  if not ngx.var.content_length then
    return
  end

  if tonumber(ngx.var.content_length) > self.request_limit then
      ngx.log(ngx.INFO, "request rejected due to large body")
      ngx.status = 413
      ngx_say("Payload Too Large")
      return ngx_exit(413)
  end
end

function _M:header_filter(context)
  if self.response_limit <= 0  then
    return
  end

  -- Not content-length header in Upstream response, skip it
  if not ngx.var.upstream_http_content_length then
    return
  end

  if tonumber(ngx.var.upstream_http_content_length) > self.response_limit then
      ngx.log(ngx.INFO, "Response rejected due to large body")
      context.request_limited = true;
      ngx.status = 413
      return ngx_exit(413)
  end
end

function _M:body_filter(context)
  if context.request_limited then
    ngx.arg[1] = "Payload Too Large"
    ngx.arg[2] = true
    return
  end
end

return _M
