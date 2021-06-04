local _M  = require('apicast.policy').new('Nginx Filter Policy', 'builtin')
local new = _M.new
local get_headers = ngx.req.get_headers

function _M.new(config)
  local self = new(config)
  self.headers = {}
  self.validate = false
  for _,val in pairs(config.headers or {}) do
    self.headers[val.name] = val.append
    self.validate = true
  end
  return self
end

function _M:rewrite(context)
  if not self.validate then
    return
  end

  local headers = get_headers()
  context.nginx_filters_headers = {}

  for header_name,append in pairs(self.headers) do
      local original_header = headers[header_name]
      if original_header then
        ngx.req.clear_header(header_name)
        if append then
          context.nginx_filters_headers[header_name] = original_header
        end
      end
  end
end

function _M:access(context)
  if not self.validate then
    return
  end

  for header_name, val in pairs(context.nginx_filters_headers) do
    ngx.req.set_header(header_name, val)
  end
end

return _M
