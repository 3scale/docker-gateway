-----------------
--- Service configuration object.
-- @classmod Service

local setmetatable = setmetatable
local tostring = tostring
local rawget = rawget
local lower = string.lower
local gsub = string.gsub
local select = select
local re = require 'ngx.re'

local http_authorization = require 'resty.http_authorization'

local oauth = require('apicast.oauth')
local mapping_rules_matcher = require('apicast.mapping_rules_matcher')

local _M = { }
local mt = { __index = _M  }

function _M.new(attributes)
  return setmetatable(attributes or {}, mt)
end

local http_methods_with_body = {
  POST = true,
  PUT = true,
  PATCH = true
}

local function read_body_args(...)
  local method = ngx.req.get_method()

  if not http_methods_with_body[method] then
    return {}, 'not supported'
  end

  ngx.req.read_body()

  local args, err = ngx.req.get_post_args()

  if not args then
    ngx.log(ngx.NOTICE, 'Error while getting post args: ', err)
    args = {}
  end

  local results = {}

  for n=1, select('#', ...) do
    results[n] = args[select(n, ...)]
  end

  return results
end

local function read_http_header(name)
  local normalized = gsub(lower(name), '-', '_')
  return ngx.var['http_' .. normalized]
end

local function tuple_mt(size)
  return { __len = function() return size end }
end

local credentials_v2_mt = tuple_mt(2)
local credentials_v1_mt = tuple_mt(1)
local credentials_oauth_mt = tuple_mt(1)

local backend_version_credentials = { }

function backend_version_credentials.version_1(config)
  local name = (config.user_key or 'user_key')
  local user_key

  if config.location == 'query' then
    user_key = ngx.var['arg_' .. name] or read_body_args(name)[1]

  elseif config.location == 'headers' then
    user_key = read_http_header(name)

  elseif config.location == 'authorization' then
    local auth = http_authorization.new(ngx.var.http_authorization)

    user_key = auth.userid or auth.password or auth.token
  else
    return nil, 'invalid credentials location'
  end
  ------
  -- user_key credentials.
  -- @field 1 User Key
  -- @field user_key User Key
  -- @table credentials_v1
  return setmetatable({ user_key, user_key = user_key }, credentials_v1_mt)
end

function backend_version_credentials.version_2(config)
  local app_id_name = (config.app_id or 'app_id')
  local app_key_name = (config.app_key or 'app_key')

  local app_id, app_key

  if config.location == 'query' then
    app_id = ngx.var['arg_' .. app_id_name]
    app_key = ngx.var['arg_' .. app_key_name]

    if not app_id or not app_key then
      local body = read_body_args(app_id_name, app_key_name)

      app_id = app_id or body[1]
      app_key = app_key or body[2]
    end
  elseif config.location == 'headers' then
    app_id = read_http_header(app_id_name)
    app_key = read_http_header(app_key_name)

  elseif config.location == 'authorization' then
    local auth = http_authorization.new(ngx.var.http_authorization)

    app_id = auth.userid or auth.token
    app_key = auth.password
  else
    return nil, 'invalid credentials location'
  end

  ------
  -- app\_id/app\_key credentials.
  -- @field 1 app id or app key
  -- @field[opt] 2
  -- @field app_id App ID
  -- @field app_key App Key
  -- @table credentials_v2
  return setmetatable({ app_id, app_key, app_id = app_id, app_key = app_key }, credentials_v2_mt)
end

function backend_version_credentials.version_oauth(config)
  local name = (config.access_token or 'access_token')
  local authorization = http_authorization.new(ngx.var.http_authorization)
  local access_token

  if config.location == 'query' then
    access_token = ngx.var['arg_' .. name] or read_body_args(name)[1]

  elseif config.location == 'headers' then
    access_token = read_http_header(name)

  elseif config.location == 'authorization' then
    access_token = authorization.token

  else
    return nil, 'invalid credentials location'
  end

  -- https://tools.ietf.org/html/rfc6750#section-2.1 says:
  -- Resource servers MUST support this method. [Bearer]
  access_token = access_token or authorization.token

  ------
  -- oauth credentials.
  -- @field 1 Access Token
  -- @field access_token Access Token
  -- @table credentials_oauth
  return setmetatable({ access_token, access_token = access_token }, credentials_oauth_mt)
end

-- Returns a table with the args included in the request. If it's a GET, it
-- returns the args in the URI. Otherwise, it returns the args in the body.
-- According to the specs, it's possible to define mapping rules like:
-- POST /some_path?a_param={a_value}
-- That match a request like POST "http://apicast_host:8080/some_path" with
-- a form URL-encoded body like: "a_param=abc".
-- That's the reason why we need to read the body.
local function get_request_params(method)
  local params = ngx.req.get_uri_args()

  if method == "GET" then
    return params
  else
    ngx.req.read_body()
    local body_params, err = ngx.req.get_post_args()

    if not body_params then
      ngx.log(ngx.NOTICE, 'Error while getting post args: ', err)
      body_params = {}
    end

    -- Adds to body_params URI params that are not included in the body. Doing
    -- the reverse would be more expensive, because in general, we expect the
    -- size of body_params to be larger than the size of params.
    setmetatable(body_params, { __index = params })

    return body_params
  end
end

-- This table can be used with `table.concat` to serialize
-- just the numeric keys, but also with `pairs` to iterate
-- over just the non numeric keys (for query building).

--- extracts credentials from the current request
-- @return @{credentials_v1}, @{credentials_v2}, or @{credentials_oauth}
-- @return[opt] error message why credentials could not be extracted
function _M:extract_credentials()
  local backend_version = tostring(self.backend_version)
  local credentials = rawget(self, 'credentials')

  if not credentials then
    return nil, 'missing credentials'
  end

  local extractor = backend_version_credentials['version_' .. backend_version]

  if not extractor then
   return nil, 'invalid backend version: ' .. backend_version
  end

  return extractor(credentials)
end

function _M:oauth()
  local authentication = self.authentication_method or self.backend_version

  if authentication == 'oidc' then
    return oauth.oidc.new(self.oidc)
  elseif authentication == 'oauth' then
    return oauth.apicast.new(self)
  else
    return nil, 'not oauth'
  end
end

local function extract_usage_v2(config, method, path)
  local rules = config.rules

  ngx.log(ngx.DEBUG, '[mapping] service ', config.id, ' has ', #rules, ' rules')

  local args = get_request_params(method)
  return mapping_rules_matcher.get_usage_from_matches(method, path, args, rules)
end

-- Deprecated
function _M:extract_usage(request)
  ngx.log(ngx.WARN, 'extract_usage is deprecated, please use get_usage(method, path)')
  local req = re.split(request, " ", 'oj')
  local method, url = req[1], req[2]
  local path = re.split(url, "\\?", 'oj')[1]

  return extract_usage_v2(self, method, path)
end

--- Get the usage associated with a request
-- @tparam string method Method of the request (GET, POST, etc.)
-- @tparam string path Path of the request
function _M:get_usage(method, path)
  -- This is a simple dispatcher. If it detects that the 'extract_usage' method
  -- has been defined, it calls it. Otherwise, it calls the new version of the
  -- method. This is done to keep backwards compatibility, because in previous
  -- versions it was possible to ovewrite that method and expect to be called
  -- from where get_usage is currently being called.

  if self.extract_usage and self.extract_usage ~= _M.extract_usage then
    return self:extract_usage(ngx.var.request)
  else
    return extract_usage_v2(self, method, path)
  end
end

return _M
