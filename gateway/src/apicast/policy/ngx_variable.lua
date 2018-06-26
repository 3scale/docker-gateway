local _M = {}

local function context_values()
  return {
    uri = ngx.var.uri,
    host = ngx.var.host,
    remote_addr = ngx.var.remote_addr,
    request_method = ngx.req.get_method()
  }
end

function _M.available_context(policies_context)
  return setmetatable(context_values(), { __index = policies_context })
end

return _M
