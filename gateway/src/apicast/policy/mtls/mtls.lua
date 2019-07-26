local policy = require('apicast.policy')
local _M = policy.new('mtls')
local X509 = require('resty.openssl.x509')
local errors = require('apicast.errors')
local re_split = require('ngx.re').split

local mt = {
  __index = _M
}

local function encode(bytes)
  local encoded = ngx.encode_base64(bytes)
  return re_split(encoded, '=')[1]
end

local function check_certificate(cert, cnf)
  if not (cert and cnf) then return false end

  if encode(cert:digest('SHA256')) == cnf['x5t#S256'] then return true end

  return false
end

function _M.new()
  return setmetatable({
  }, mt)
end

function _M.access(context)
  if not context.jwt then return errors.authorization_failed(context.service) end

  local cert = X509.parse_pem_cert(ngx.var.ssl_client_raw_cert)

  if not check_certificate(cert, context.jwt.cnf) then
    return errors.authorization_failed(context.service)
  end

  return true
end

return _M
