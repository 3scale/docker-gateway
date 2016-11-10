local _M = require 'plugin'

local provider = _M.provider

function _M.post_action()
  provider.post_action()
end

function _M.access()
  local fun = provider.call()
  return fun()
end

function _M.body_filter()
  ngx.ctx.buffered = (ngx.ctx.buffered or "") .. string.sub(ngx.arg[1], 1, 1000)

  if ngx.arg[2] then
    ngx.var.resp_body = ngx.ctx.buffered
  end
end

function _M.header_filter()
  ngx.var.resp_headers = require('cjson').encode(ngx.resp.get_headers())
end

return _M
