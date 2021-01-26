local policy = require('apicast.policy')
local _M = policy.new('http_proxy', 'builtin')

local resty_url = require 'resty.url'
local ipairs = ipairs

local new = _M.new

local proxies = {"http", "https"}

function _M.new(config)
  local self = new(config)
  self.proxies = {}

  if config.all_proxy then
    local err
    self.all_proxy, err =  resty_url.parse(config.all_proxy)
    if err then
      ngx.log(ngx.WARN, "All proxy '", config.all_proxy, "' is not correctly defined, err:", err)
    end
  end

  for _, proto in ipairs(proxies) do
    local val, err =  resty_url.parse(config[string.format("%s_proxy", proto)])
    if err then
      ngx.log(ngx.WARN, proto, " proxy is not correctly defined, err: ", err)
    end
    self.proxies[proto] = val or self.all_proxy
  end
  return self
end

local function find_proxy(self, scheme)
  return self.proxies[scheme]
end

function _M:access(context)
  context.skip_https_connect_on_proxy = true

  local upstream = context.get_upstream()
  if not upstream then
    return
  end

  upstream:set_skip_https_connect_on_proxy()
end

function _M:export()
  -- This get_http_proxy function will be called in upstream just in case if a
  -- proxy is defined.
  return  {
    get_http_proxy = function(uri)
      if not uri.scheme then
        return nil
      end
      return find_proxy(self, uri.scheme)
    end
  }
end

return _M
