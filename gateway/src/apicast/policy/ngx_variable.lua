local LinkedList = require('apicast.linked_list')

local _M = {}

local function context_values()
  return {
    uri = ngx.var.uri,
    path = ngx.var.path,
    host = ngx.var.host,
    remote_addr = ngx.var.remote_addr,
    remote_port = ngx.var.remote_port,
    scheme = ngx.var.scheme,
    server_addr = ngx.var.server_addr,
    server_port = ngx.var.server_port,
    headers = ngx.req.get_headers(),
    http_method = ngx.req.get_method(),
  }
end

function _M.available_context(policies_context)
  return LinkedList.readonly(context_values(), policies_context)
end

return _M
