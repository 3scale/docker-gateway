--local get_token = require 'apicast.oauth.apicast_oauth.get_token'
--local callback = require 'apicast.oauth.apicast_oauth.authorized_callback'
local authorize = require 'apicast.oauth.apicast_oauth.authorize'
local router = require 'router'
local jwt = require 'resty.jwt'

local setmetatable = setmetatable

local _M = {
  _VERSION = '0.1'
}

local mt = {
  __index = _M,
  __tostring = function()
    return 'APIcast OAuth 2.0'
  end,
}

function _M.new(service)
  return setmetatable({
    authorize = authorize.call,
    --      callback = callback.call,
    --      get_token = get_token.call,
    service = service,
  }, mt)
end

local function parse_and_verify_token(jwt_token)
  local jwt_obj = jwt:load_jwt(jwt_token)
  if not jwt_obj.valid then
    ngx.log(ngx.NOTICE, jwt_obj.reason)
    return jwt_obj, 'JWT not valid'
  end
  return jwt_obj
end

function _M.transform_credentials(_, credentials)
  local jwt_obj, err = parse_and_verify_token(credentials.access_token)
  ngx.log(ngx.NOTICE, ' err ', err)
  if (not err and jwt_obj and jwt_obj.payload) then
    credentials.access_token = jwt_obj.payload.clientToken
  end
  return credentials
end


function _M:router(service)
  local oauth = self
  local r = router:new()

  r:get('/authorize', function() oauth:authorize(service) end)
  r:post('/authorize', function() oauth:authorize(service) end)

  -- TODO: only applies to apicast oauth...
  --  r:post('/callback', function() oauth:callback() end)
  --  r:get('/callback', function() oauth:callback() end)

  --  r:post('/oauth/token', function() oauth:get_token(service) end)

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
