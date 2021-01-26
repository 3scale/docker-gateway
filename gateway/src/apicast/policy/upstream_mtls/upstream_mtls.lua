-- This policy enables MTLS with the upstream API endpoint

local ssl = require('ngx.ssl')
local ffi = require "ffi"
local base = require "resty.core.base"
local data_url = require('resty.data_url')

local C = ffi.C
local get_request = base.get_request
local open = io.open


ffi.cdef([[
  int ngx_http_apicast_ffi_set_proxy_cert_key(
    ngx_http_request_t *r, void *cdata_chain, void *cdata_key);
]])


local policy = require('apicast.policy')
local _M = policy.new('mtls', "builtin")

local path_type = "path"
local embedded_type = "embedded"

local new = _M.new


local function read_file(path)
  ngx.log(ngx.DEBUG, "reading path:", path)

  local file = open(path, "rb")
  if not file then
    ngx.log(ngx.ERR, "Cannot read path: ", path)
    return nil
  end

  local content = file:read("*a")
  file:close()
  return content
end


local function get_cert(value, value_type)
  if value_type == path_type then
    return read_file(value)
  end

  if value_type == embedded_type then
    local parsed_data, err = data_url.parse(value)
    if err then
      ngx.log(ngx.ERR, "Cannot parse certificate content: ", err)
      return nil
    end
    return parsed_data.data
  end
end

local function read_certificate(value, value_type)
  local data = get_cert(value, value_type)
  if data == nil then
    ngx.log(ngx.ERR, "Certificate value is invalid")
    return
  end
  return ssl.parse_pem_cert(data)
end

local function read_certificate_key(value, value_type)

  local data = get_cert(value, value_type)

  if data == nil then
    ngx.log(ngx.ERR, "Certificate value is invalid")
    return
  end

  if data == nil then
    ngx.log(ngx.ERR, "Certificate key value is invalid")
    return
  end

  return ssl.parse_pem_priv_key(data)

end

function _M.new(config)
  local self = new(config)
  if config == nil then
    config = {}
  end

  self.cert = read_certificate(
    config.certificate,
    config.certificate_type or path_type)
  self.cert_key = read_certificate_key(
    config.certificate_key,
    config.certificate_key_type or path_type)
  return self
end


-- Set the certs for the upstream connection. Need to receive the pointers from
-- parse_* functions.
--- Public function to be able to unittest this.
function _M.set_certs(cert, key)
  local r = get_request()
  if not r then
    ngx.log(ngx.ERR, "Invalid request")
    return
  end

  local val = C.ngx_http_apicast_ffi_set_proxy_cert_key(r, cert, key)
  if val ~= ngx.OK then
    ngx.log(ngx.ERR, "Certificate cannot be set correctly")
  end
end

function _M:balancer(context)
  if self.cert and self.cert_key then
    self.set_certs(self.cert, self.cert_key)
  end
end

return _M
