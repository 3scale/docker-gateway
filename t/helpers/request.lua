local tls = require "http.tls"
local assert = require('luassert')

local setmetatable = setmetatable

local original_tls_context = tls.new_client_context

local _M = {}

local response = {}
local response_mt = { __index = response}

function response.New(headers, stream)

  if not headers then
    return nil, "Not a valid headers"
  end

  local self = setmetatable({}, response_mt)
  self.headers = headers
  self.stream = stream
  return self
end

function response:status()
  return self.headers:get(":status")
end

function response:is_http2_request()
  return tostring(self.stream.connection) == 'http.h2_connection{type="client"}'
end

function response:body()
  if self.body_string then
    return self.body_string
  end

  local body, err = self.stream:get_body_as_string()
  if not body and err then
    return nil, "No body in the request" .. err
  end

  self.body_string = body
  return body
end

function response:expect200()
  assert.same(self:status(), "200", "Status mistmatch")
end

function response:expectHTTP2()
  assert.same(self:is_http2_request(), true, "Is not http2 connection")
end

function response:expectBody(body)
  assert.same(self:body(), body, "BODY content mistmatch")
end



function _M.request(uri, method, ssl_cert, req_body, headers)
  if ssl_cert then
    tls.new_client_context = function()
      local ctx = original_tls_context()
      local store = ctx:getStore()
      store:add(ssl_cert)
      ngx.log(ngx.INFO, "[TEST-HELPERS]: Added ssl_cert '"..ssl_cert.."' to the openssl store")
      return ctx
    end
  end

  -- Imported here to add the ssl_cert before ask for that.
  local http_request = require "http.request"

  local req = http_request.new_from_uri(uri)

  local request_method = method or "GET"
  req.headers:upsert(":method", string.upper(request_method))


  if headers then
    for key, value in pairs(headers) do
      req.headers:upsert(tostring(key), tostring(value))
    end
  end
  --
  if req_body then
    req:set_body(req_body)
  end

  local resp_headers, stream = req:go(10)
  local resp, err = response.New(resp_headers, stream)
  if err then
    return nil, "Not a valid request"
  end

  return resp
end

return _M
