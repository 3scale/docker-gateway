local JWT = require 'resty.jwt'
local jwt_validators = require 'resty.jwt-validators'

local lrucache = require 'resty.lrucache'
local util = require 'apicast.util'
local TemplateString = require 'apicast.template_string'

local setmetatable = setmetatable
local ngx_now = ngx.now
local format = string.format
local type = type
local tostring = tostring
local assert = assert

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

local empty = {}

function _M.new(oidc_config, service)
  local oidc = oidc_config or empty
  local issuer = oidc.issuer
  local config = oidc.config or empty
  local alg_values = config.id_token_signing_alg_values_supported or empty
  local tmpl, tmpl_err
  local err

  if  oidc_config and oidc_config.client_id then
     tmpl, tmpl_err = TemplateString.new(oidc_config.client_id, "liquid")
    if tmpl_err then
      err = 'Invalid client_id template string'
    end
  end

  if not issuer or #alg_values == 0 then
    err = 'missing OIDC configuration'
  end

  return setmetatable({
    config = config,
    issuer = issuer,
    service = service,
    tmpl = tmpl,
    keys = oidc.keys or empty,
    clock = ngx_now,
    alg_whitelist = util.to_hash(alg_values),
    -- https://tools.ietf.org/html/rfc7523#section-3
    jwt_claims = {
      -- 1. The JWT MUST contain an "iss" (issuer) claim that contains a
      -- unique identifier for the entity that issued the JWT.
      iss = jwt_validators.chain(jwt_validators.required(), issuer and jwt_validators.equals_any_of({ issuer })),

      -- 2. The JWT MUST contain a "sub" (subject) claim identifying the
      -- principal that is the subject of the JWT.
      sub = jwt_validators.required(),

      -- 3. The JWT MUST contain an "aud" (audience) claim containing a
      -- value that identifies the authorization server as an intended
      -- audience.
      aud = jwt_validators.required(),

      -- 4. The JWT MUST contain an "exp" (expiration time) claim that
      -- limits the time window during which the JWT can be used.
      exp = jwt_validators.is_not_expired(),

      -- 5. The JWT MAY contain an "nbf" (not before) claim that identifies
      -- the time before which the token MUST NOT be accepted for
      -- processing.
      nbf = jwt_validators.opt_is_not_before(),

      -- 6. The JWT MAY contain an "iat" (issued at) claim that identifies
      -- the time at which the JWT was issued.
      iat = jwt_validators.opt_greater_than(0),

      -- This is keycloak-specific. Its tokens have a 'typ' and we need to verify
      typ = jwt_validators.opt_equals_any_of({ 'Bearer' }),
    },
  }, mt), err
end

local function timestamp_to_seconds_from_now(expiry, clock)
  local time_now = (clock or ngx_now)()
  local ttl = expiry and (expiry - time_now) or nil
  return ttl
end

local function find_public_key(jwt, keys)
  local jwk = keys and keys[jwt.header.kid]
  if jwk then return jwk.pem end
end

-- Parses the token - in this case we assume it's a JWT token
-- Here we can extract authenticated user's claims or other information returned in the access_token
-- or id_token by RH SSO
local function parse_and_verify_token(self, namespace, jwt_token)
  local cache = self.cache

  if not cache then
    return nil, 'not initialized'
  end
  local cache_key = format('%s:%s', namespace or '<empty>', jwt_token)

  local jwt = self:parse(jwt_token, cache_key)

  if jwt.verified then
    return jwt
  end

  local _, err = self:verify(jwt, cache_key)

  return jwt, err
end

function _M:parse_and_verify(access_token, cache_key)
  local jwt_obj, err = parse_and_verify_token(self, assert(cache_key, 'missing cache key'), access_token)

  if err then
    if ngx.config.debug then
      ngx.log(ngx.DEBUG, 'JWT object: ', require('inspect')(jwt_obj), ' err: ', err, ' reason: ', jwt_obj.reason)
    end
    return nil, jwt_obj and jwt_obj.reason or err
  end

  return jwt_obj
end

local jwt_mt = {
  __tostring = function(jwt)
    return jwt.token
  end
}

local function load_jwt(token)
  local jwt = JWT:load_jwt(tostring(token))

  jwt.token = token

  return setmetatable(jwt, jwt_mt)
end

function _M:parse(jwt, cache_key)
  local cached = cache_key and self.cache:get(cache_key)

  if cached then
    ngx.log(ngx.DEBUG, 'found JWT in cache for ', cache_key)
    return cached
  end

  return load_jwt(jwt)
end

function _M:verify(jwt, cache_key)
  if not jwt then
    return false, 'JWT missing'
  end

  if not jwt.valid then
    ngx.log(ngx.WARN, jwt.reason)
    return false, 'JWT not valid'
  end

  if not self.alg_whitelist[jwt.header.alg] then
    return false, '[jwt] invalid alg'
  end

  -- TODO: this should be able to use DER format instead of PEM
  local pubkey = find_public_key(jwt, self.keys)

  jwt = JWT:verify_jwt_obj(pubkey, jwt, self.jwt_claims)

  if not jwt.verified then
    ngx.log(ngx.DEBUG, "[jwt] failed verification for token, reason: ", jwt.reason)
    return false, "JWT not verified"
  end

  if cache_key then
    ngx.log(ngx.DEBUG, 'adding JWT to cache ', cache_key)
    local ttl = timestamp_to_seconds_from_now(jwt.payload.exp, self.clock)
    -- use the JWT itself in case there is no cache key
    self.cache:set(cache_key, jwt, ttl)
  end

  return true
end

function _M:transform_credentials(credentials, cache_key)
  local jwt_obj, err = self:parse_and_verify(credentials.access_token, cache_key or '<shared>')

  if err then
    return nil, nil, nil, err
  end

  local payload = jwt_obj.payload
  local app_id = payload.azp

  if self.tmpl then
      app_id = self.tmpl:render(payload)
  end

  local ttl = timestamp_to_seconds_from_now(payload.exp)

  if type(app_id) == 'table' then
    app_id = app_id[1]
  end

  ------
  -- OAuth2 credentials for OIDC
  -- @field app_id Client id
  -- @table credentials_oauth
  return { app_id = app_id }, ttl, payload
end



return _M
