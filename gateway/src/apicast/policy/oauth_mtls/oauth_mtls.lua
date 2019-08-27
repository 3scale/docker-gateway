local policy = require('apicast.policy')
local _M = policy.new('oauth_mtls', 'builtin')
local X509 = require('resty.openssl.x509')
local b64 = require('ngx.base64')

-- The "x5t#S256" (X.509 Certificate SHA-256 Thumbprint) Header
-- Parameter is a base64url encoded SHA-256 thumbprint (a.k.a. digest)
-- of the DER encoding of the X.509 certificate.
-- https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#section-4.1.8
local header_parameter = 'x5t#S256'

local function error(service)
  ngx.log(ngx.INFO, 'oauth_mtls failed for service ', service and service.id)
  ngx.var.cached_key = nil
  ngx.status = ngx.HTTP_UNAUTHORIZED
  ngx.header.content_type = 'application/json; charset=utf-8'
  ngx.print('{"error": "invalid_token"}')
  ngx.exit(ngx.status)
end

local function check_certificate(cert, cnf)
  if not (cert and cnf) then return false end
  return b64.encode_base64url(cert:digest('SHA256')) == cnf[header_parameter]
end

local new = _M.new

function _M.new(config)
  local self = new(config)
  return self
end

function _M.access(_, context)
  if not context.jwt then return error(context.service or {}) end

  local cert = X509.parse_pem_cert(ngx.var.ssl_client_raw_cert)

  if not check_certificate(cert, context.jwt.cnf) then
    return error(context.service or {})
  end

  return true
end

return _M
