local jwt = require 'resty.jwt'
local jwt_validators = require 'resty.jwt-validators'

local http_ng = require 'resty.http_ng'
local user_agent = require 'user_agent'
local resty_env = require 'resty.env'
local cjson = require 'cjson'

local lrucache = require 'resty.lrucache'
local util = require 'util'
local router = require 'router'

local setmetatable = setmetatable
local len = string.len
local ngx_now = ngx.now
local format = string.format

local _M = {
  cache_size = 10000,
}

function _M.reset()
  _M.cache = lrucache.new(_M.cache_size)
end

_M.reset()

local mt = {
  __index = _M,
  __tostring = function()
    return 'OpenID Connect'
  end
}

local token_key_format = '%s:%s'
local introspection_key_format = 'intro:%s:%s'
local revoked_key_format = 'revoked:%s:%s'

function _M.new(service, options)
  local oidc = service.oidc
  local issuer = oidc.issuer or oidc.issuer_endpoint
  local config = oidc.config or {}
  local openid = config.openid or {}

  local opts = options or {}
  local http_client = http_ng.new{
    backend = opts.client,
    options = {
      headers = { ['User-Agent'] = user_agent() },
      ssl = { verify = resty_env.enabled('OPENSSL_VERIFY') }
    }
  }

  config.introspection_enabled = opts.introspection_enabled or resty_env.enabled('APICAST_TOKEN_INTROSPECTION_ENABLED')

  return setmetatable({
    service = service,
    config = config,
    issuer = issuer,
    clock = ngx_now,
    alg_whitelist = util.to_hash(openid.id_token_signing_alg_values_supported),
    jwt_claims = {
      nbf = jwt_validators.is_not_before(),
      exp = jwt_validators.is_not_expired(),
      aud = jwt_validators.required(),
      iss = jwt_validators.equals_any_of({ issuer }),
    },
    http_client = http_client,
  }, mt)
end

local function timestamp_to_seconds_from_now(expiry, clock)
  local time_now = (clock or ngx_now)()
  local ttl = expiry and (expiry - time_now) or nil
  return ttl
end

-- Formats the realm public key string into Public Key File (PKCS#8) format
local function format_public_key(key)
  if not key then
    return nil, 'missing key'
  end

  local formatted_key = "-----BEGIN PUBLIC KEY-----\n"
  local key_len = len(key)
  for i=1,key_len,64 do
    formatted_key = formatted_key..string.sub(key, i, i+63).."\n"
  end
  formatted_key = formatted_key.."-----END PUBLIC KEY-----"
  return formatted_key
end

local function introspect_token(self, jwt_token)
  local openid_configuration = self.config.openid

  if not openid_configuration then
    return false
  end

  local cache = self.cache
  local introspect_key = format(introspection_key_format,self.service.id,  jwt_token)

  local token_info = cache:get(introspect_key)
  if token_info then
     return token_info.active
  end

  local introspection_url = openid_configuration.token_introspection_endpoint
  local user = openid_configuration.client_id
  local pass = openid_configuration.client_secret
  local credential = "Basic " .. ngx.encode_base64(table.concat({ user or '', pass or '' }, ':'))
  local opts = {
    headers = {
      ['Authorization'] = credential
    }
  }

  local res, err = self.http_client.post(introspection_url , { token = jwt_token, token_type_hint = 'access_token'}, opts)
  if not res and err then
    ngx.log(ngx.WARN, 'token introspection error: ', err, ' url: ', introspection_url)
    return false
  end

  token_info = cjson.decode(res.body)
  cache:set(introspect_key)
  return token_info.active
end

local function logout_from_idp(self)
  local openid_configuration = self.config.openid

  ngx.req.read_body()
  local data = ngx.req.get_body_data() or ''
  local args = ngx.decode_args(data)

  local logout_url = openid_configuration.end_session_endpoint
  local client_id = openid_configuration.client_id
  local client_secret = openid_configuration.client_secret
  local refresh_token = args.refresh_token
  return self.http_client.post(logout_url, {client_id = client_id, client_secret=client_secret, refresh_token=refresh_token})
end

-- Parses the token - in this case we assume it's a JWT token
-- Here we can extract authenticated user's claims or other information returned in the access_token
-- or id_token by RH SSO
local function parse_and_verify_token(self, jwt_token)
  local cache = self.cache

  if not cache then
    return nil, 'not initialized'
  end

  local revoked_key = format(revoked_key_format, self.service.id, jwt_token)
  local revoked = cache:get(revoked_key)

  if revoked then
    ngx.log(ngx.DEBUG, "JWT was revoked")
    return nil, 'token was revoked'
  end

  local cache_key = format(token_key_format, self.service.id, jwt_token)

  local jwt_obj = cache:get(cache_key)

  if jwt_obj then
    ngx.log(ngx.DEBUG, 'found JWT in cache for ', cache_key)
    return jwt_obj
  end

  jwt_obj = jwt:load_jwt(jwt_token)

  if not jwt_obj.valid then
    ngx.log(ngx.WARN, jwt_obj.reason)
    return jwt_obj, 'JWT not valid'
  end

  if not self.alg_whitelist[jwt_obj.header.alg] then
    return jwt_obj, '[jwt] invalid alg'
  end
  -- TODO: this should be able to use DER format instead of PEM
  local pubkey = format_public_key(self.config.public_key)

  jwt_obj = jwt:verify_jwt_obj(pubkey, jwt_obj, self.jwt_claims)

  if not jwt_obj.verified then
    ngx.log(ngx.DEBUG, "[jwt] failed verification for token, reason: ", jwt_obj.reason)
    return jwt_obj, "JWT not verified"
  end
  local token_introspection_enabled = self.config.introspection_enabled
  if token_introspection_enabled and not introspect_token(self, jwt_token) then
    return nil, '[jwt] JWT is not active'
  end

  ngx.log(ngx.DEBUG, 'adding JWT to cache ', cache_key)
  local ttl = timestamp_to_seconds_from_now(jwt_obj.payload.exp, self.clock)
  cache:set(cache_key, jwt_obj, ttl)

  return jwt_obj
end

function _M:revoke_credentials(service)
  local credentials, err = service:extract_credentials()
  if err then
    ngx.status = 401
    ngx.print(err)
    ngx.exit(ngx.HTTP_UNAUTHORIZED)
  end
  local jwt_obj, jwt_err = parse_and_verify_token(self, credentials.access_token)
  if jwt_err then
    ngx.status = 401
    ngx.print(err)
    ngx.exit(ngx.HTTP_UNAUTHORIZED)
  end
  local res, logout_err = logout_from_idp(self)
  ngx.log(ngx.DEBUG, res.status)
  if res.status ~= 204 then
    ngx.status = res.status
    ngx.print(res.body or logout_err)
    ngx.exit(res.status)
  end

  local cache = self.cache
  local cache_key = format(token_key_format, service.id, credentials.access_token)
  cache:delete(cache_key)

  local introspect_key = format(introspection_key_format, service.id, credentials.access_token)
  cache:delete(introspect_key)

  local revoked_key = format(revoked_key_format, service.id, credentials.access_token)
  local ttl = timestamp_to_seconds_from_now(jwt_obj.payload.exp, self.clock)
  cache:set(revoked_key, credentials.access_token, ttl)
  ngx.say("logout success")
  ngx.exit(ngx.HTTP_OK)

end

function _M:transform_credentials(credentials)
  local jwt_obj, err = parse_and_verify_token(self, credentials.access_token)

  if err then
    if ngx.config.debug then
      ngx.log(ngx.DEBUG, 'JWT object: ', require('inspect')(jwt_obj))
    end
    return nil, nil, jwt_obj and jwt_obj.reason or err
  end

  local payload = jwt_obj.payload

  local app_id = payload.azp or payload.aud
  local ttl = timestamp_to_seconds_from_now(payload.exp)


  --- http://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken
  -- It MAY also contain identifiers for other audiences.
  -- In the general case, the aud value is an array of case sensitive strings.
  -- In the common special case when there is one audience, the aud value MAY be a single case sensitive string.
  if type(app_id) == 'table' then
    app_id = app_id[1]
  end

  ------
  -- OAuth2 credentials for OIDC
  -- @field app_id Client id
  -- @table credentials_oauth
  return { app_id = app_id }, ttl
end

function _M:router(service)
  local oidc = self
  local r = router:new()

  r:post('/oidc/logout', function() oidc:revoke_credentials(service) end)
  return r
end

function _M:call(service, method, uri, ...)
  local r = self:router(service)

  local f, params = r:resolve(method or ngx.req.get_method(),
    uri or ngx.var.uri,
    unpack(... or {}))

  return f, params
end

return _M
