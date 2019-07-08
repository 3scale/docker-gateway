-- OpenID Connect Authentication policy
-- It will verify JWT signature against a list of public keys
-- discovered through OIDC Discovery from the IDP.

local lrucache = require('resty.lrucache')
local OIDC = require('apicast.oauth.oidc')
local oidc_discovery = require('resty.oidc.discovery')
local http_authorization = require('resty.http_authorization')
local resty_url = require('resty.url')
local policy = require('apicast.policy')
local _M = policy.new('oidc_authentication', 'builtin')

local tostring = tostring

_M.cache_size = 100

function _M.init()
  _M.cache = lrucache.new(_M.cache_size)
end

local function valid_issuer_endpoint(endpoint)
  return resty_url.parse(endpoint) and endpoint
end

local new = _M.new
--- Initialize a oidc_authentication
-- @tparam[opt] table config Policy configuration.
function _M.new(config)
  local self = new(config)

  self.issuer_endpoint = valid_issuer_endpoint(config and config.issuer_endpoint)
  self.discovery = oidc_discovery.new(self.http_backend)

  self.oidc = (config and config.oidc) or OIDC.new(self.discovery:call(self.issuer_endpoint))

  self.required = config and config.required

  return self
end

local function bearer_token()
  return http_authorization.new(ngx.var.http_authorization).token
end

function _M:rewrite(context)
  local access_token = bearer_token()

  if access_token or self.required then
    local jwt, err = self.oidc:parse(access_token)

    if jwt then
      context[self] = jwt
      context.jwt = jwt
    else
      ngx.log(ngx.WARN, 'failed to parse access token ', access_token, ' err: ', err)
    end
  end
end

local function exit_status(status)
  ngx.status = status
  -- TODO: implement content negotiation to generate proper content with an error
  return ngx.exit(status)
end

local function challenge_response()
  ngx.header.www_authenticate = 'Bearer'

  return exit_status(ngx.HTTP_UNAUTHORIZED)
end

function _M:access(context)
  local jwt = context[self]

  if not jwt or not jwt.token then
    if self.required then
      return challenge_response()
    else
      return
    end
  end

  local ok, err = self.oidc:verify(jwt)

  if not ok then
    ngx.log(ngx.INFO, 'JWT verification error: ', err, ' token: ', tostring(jwt))

    return exit_status(ngx.HTTP_FORBIDDEN)
  end

  return ok
end

return _M
