local resty_http = require 'resty.http'
local cjson = require 'cjson'
local now = ngx.now
local unpack = unpack
local getenv = os.getenv
local inspect = require 'inspect'
local _M = { _VERSION = '0.01' }

local mt = { __index = _M }

local setmetatable = setmetatable

local timestamp = function()
  return now() * 1000
end

local function post_data(uri, headers, data)
  local http = resty_http.new()

  local params = {
    method = "POST",
    headers = headers,
    body = cjson.encode(data),
    ssl_verify = false
  }
  --
  local res, err = http:request_uri(uri, params)

  if res and res.status ~= 200 then
    res.body = res.body or res.read_body()
    ngx.log(ngx.INFO, uri, '[hawkular] ', inspect(params))
    ngx.log(ngx.WARN, '[hawkular] ', inspect(res), '\n', inspect(err))
  end

  if err then
    ngx.log(ngx.ERR, '[hawkular] ', err)
  end
end

local function async_post_data(uri, headers, data)
  ngx.timer.at(0, function() post_data(uri, headers, data) end)
end

function _M.new(options)
  options = options or {}
  local entrypoint = options.entrypoint or getenv("HAWKULAR_ENTRYPOINT")
  local tenant = options.tenant or getenv("HAWKULAR_TENANT")
  local token = options.token or getenv("HAWKULAR_TOKEN")

  return setmetatable({
    entrypoint = entrypoint,
    tenant = tenant,
    token = token
  }, mt)
end

function _M.gauge(self, name, value)
  ngx.log(ngx.INFO, '[hawkular] ', name, ' => ', value)

  local uri = self.entrypoint .. '/hawkular/metrics/metrics/raw'
  local headers = {
    ['Authorization'] = 'Bearer ' .. self.token,
    ['Hawkular-Tenant'] = self.tenant,
    ['Content-Type'] = 'application/json'
  }
  local data = {
    gauges = {
      {
        id = name,
        data = {
          { value = value, timestamp = timestamp() }
        }
      }
    },
    -- counters = {}, availabilities = {}, strings = {}
  }

  async_post_data(uri, headers, data)
end

function _M.wrap(name, fun)
  return _M.new():instrument(name, fun)
end

function _M.instrument(self, name, fun)
  ngx.log(ngx.INFO, 'instrumenting method ', name)

  return function(...)
    return self:report(name, fun, ...)
  end
end

function _M.report(self, name, fun, ...)
  ngx.log(ngx.INFO, 'calling method ', name)

  local start = now()
  local ret = { fun(...) }

  local time = now() - start

  ngx.log(ngx.INFO, 'method ', name, ' finished in ', time, 's')

  self:gauge(name, time * 1000)

  return unpack(ret)
end

function _M.run(name, fun, ...)
  return _M.new():report(name, fun, ...)
end

return _M
