local ipairs = ipairs
local re = require('ngx.re')
local resty_url = require 'resty.url'

local _M = {}

local function last_caller_ip()
  return ngx.var.remote_addr
end

local function ip_from_x_real_ip_header()
  return ngx.req.get_headers()['X-Real-IP']
end

local function ip_from_x_forwarded_for_header()
  local forwarded_for = ngx.req.get_headers()['X-Forwarded-For']
  -- If the header is duplicated, get_heders() method  returns all the headers
  -- in a table instead of the string, so we only use the first one.
  if (type(forwarded_for) == "table") then
    forwarded_for = forwarded_for[1]
  end

  if not forwarded_for or forwarded_for == "" then
    return nil
  end

  -- THREESCALE-5258 forwarded_for can contain port. If port is in there IP
  -- value will not be parsed correctly, parsing as url will get the correct
  -- host
  -- `:` split is not valid in case that it's IPv6 notation.
  local host = re.split(forwarded_for, ',', 'oj')[1]
  local uri = resty_url.parse("my://".. host)
  return uri.host
end

local function ip_from_proxy_protocol_addr_variable()
  return ngx.var.proxy_protocol_addr
end

local get_ip_func = {
  last_caller = last_caller_ip,
  ["X-Real-IP"] = ip_from_x_real_ip_header,
  ["X-Forwarded-For"] = ip_from_x_forwarded_for_header,
  ["proxy_protocol_addr"] = ip_from_proxy_protocol_addr_variable
}

function _M.get_from(sources)
  for _, source in ipairs(sources or {}) do
    local func = get_ip_func[source]

    local ip = func and func()

    if ip then return ip end
  end
end

return _M
