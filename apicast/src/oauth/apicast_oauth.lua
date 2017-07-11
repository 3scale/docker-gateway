local setmetatable = setmetatable
local random = require 'resty.random'
local ts = require 'threescale_utils'
local cjson = require 'cjson'
local backend_client = require ('backend_client')
local http_authorization = require 'resty.http_authorization'
local env = require 'resty.env'

local inspect = require 'inspect'
local _M = {
  _VERSION = '0.1'
}

local mt = { __index = _M }

-- Required params for each grant type and response type.
_M.params = {
  grant_type = {
    authorization_code = {'client_id','redirect_uri','code'},
    password = {'client_id','client_secret','username','password'},
    client_credentials = {'client_id','client_secret'},
    implicit = {'client_id','redirect_uri'}
  },
  response_type = {
    code = {'client_id','redirect_uri'},
    token = {'client_id','redirect_uri'}
  }
}

function _M.new()
  return setmetatable(
    {
    }, mt)
end

function _M.extract_params()
  local params = {}
  local auth

  if ngx.var.http_authorization then
    auth = http_authorization.new(ngx.var.http_authorization)
  end

  local method = ngx.req.get_method()
  if not method == 'POST' then
    _M.respond_with_error(400, 'invalid_HTTP_method')
    return
  end

  ngx.req.read_body()
  local body_params = ngx.req.get_post_args()

  params.client_id = auth.userid or body_params.client_id
  params.client_secret = auth.password or body_params.client_secret

  params.grant_type = body_params.grant_type
  params.code = body_params.code
  params.redirect_uri = body_params.redirect_uri or body_params.redirect_url

  return params
end

function _M.transform_credentials(_, credentials)
  return credentials
end

function _M.respond_and_exit(status, body, headers)
  -- TODO: is there a better way to populate the response headers?..
  if headers then
    for name,value in pairs(headers) do
      ngx.header[name] = value
    end
  end

  ngx.status = status
  ngx.print(body)
  ngx.exit(ngx.HTTP_OK)
end

function _M.respond_with_error(status, message, description)

  --TODO: as per the RFC (https://tools.ietf.org/html/rfc6749#section-5.2) return WWW-Authenticate response header if 401
  local headers = {
    ['Content-Type'] = 'application/json;charset=UTF-8'
  }
  local err_msg = { error = message, error_description = description }
  local body = cjson.encode(err_msg)
  ngx.log(ngx.INFO, "error :" .. inspect(body))
  _M.respond_and_exit(status, body, headers)
end

-- TODO: Split error conditions up further to decide when we should respond with error and when we should redirect_with error
function _M.redirect_with_error(url, error, state)
  ngx.header.content_type = "application/x-www-form-urlencoded"
  return ngx.redirect(url,"?error=",error.error,"&error_description=",error.error_description,"&state=",state)
end

function _M.check_params(params)
  local response_type = params.response_type
  local required_params = _M.params.response_type
  if not response_type then return false, 'invalid_request' end
  if not required_params[response_type] then return false, 'unsupported_response_type' end

  for _,v in ipairs(required_params[response_type]) do
    if not params[v] then
      return false, 'invalid_request'
    end
  end

  return true
end

function _M.token_check_params(params)
  local grant_type = params.grant_type
  local required_params = _M.params.grant_type
  if not grant_type then return false, 'invalid_request' end
  if not required_params[grant_type] then return false, 'unsupported_grant_type' end

  for _,v in ipairs(required_params[grant_type]) do
    if (params[v] == "" or params[v] == nil) or not params[v] then
      return false, 'invalid_request'
    end
  end
  return true
end

function _M.check_credentials(service, params)
  local backend = backend_client:new(service)

  local args = {
      app_id = params.client_id,
      app_key = params.client_secret,
      redirect_uri = params.redirect_uri
    }

  local res = backend:authorize(args)
  return res.status == 200
end

-- returns a unique string for the client_id. it will be short lived
local function nonce(client_id)
  return ts.sha1_digest(tostring(random.bytes(20, true)) .. "#login:" .. client_id)
end

local function generate_access_token(client_id)
    local token = ts.sha1_digest(tostring(random.bytes(20, true)) .. client_id)

  return { access_token = token, token_type = "bearer", expires_in = env.get('APICAST_OAUTH_ACCESS_TOKEN_TTL') or 604800 }
end

local function persist_nonce(service_id, params)
  -- State value shared between client and gateway
  local client_state = params.state

  -- State value that will be shared between gateway and authorization server
  local n = nonce(params.client_id)

  local redis_key = service_id.."#tmp_data:"..n
  local client_data = {
    client_id = params.client_id,
    redirect_uri = params.redirect_uri,
    plan_id = params.scope,
    state = client_state,
    grant = params.response_type
  }

  local redis = ts.connect_redis()

  if redis then
    redis:hmset(redis_key, client_data )
    ts.release_redis(redis)
  end

  -- Overwrite state to nonce value to share state between gateway and auth server
  params.state = n
end

-- Retrieve client data from Redis
local function retrieve_client_data(service_id, params)
  local tmp_data = service_id .. "#tmp_data:".. params.state
  local client_data
  local redis = ts.connect_redis()

  if redis then
    local ok, err = redis:hgetall(tmp_data)

    if not ok then
      ngx.log(0, "no values for tmp_data hash: ".. ts.dump(err))
      ngx.header.content_type = "application/x-www-form-urlencoded"
      return ngx.redirect(params.redirect_uri .. "#error=invalid_request&error_description=invalid_or_expired_state&state=" .. (params.state or ""))
    end

    -- Restore client data
    client_data = redis:array_to_hash(ok)  -- restoring client data
    -- Delete the tmp_data:
    redis:del(tmp_data)
    ts.release_redis(redis)
  end

  return client_data
end

-- Returns the code to the client
local function send_code(client_data, code)
  ngx.header.content_type = "application/x-www-form-urlencoded"
  return ngx.redirect( client_data.redirect_uri .. "?code="..code.."&state=" .. (client_data.state or ""))
end

local function persist_code(client_data, code)
  local ok, err
  local redis = ts.connect_redis()

  if redis then
    ok, err = redis:hmset("c:".. code, {
      client_id = client_data.client_id,
      client_secret = client_data.secret_id,
      redirect_uri = client_data.redirect_uri,
      code = code
    })

    if ok then
      return redis:expire("c:".. code, 60 * 10) -- code expires in 10 mins
    else
      return ok, err
    end

  end
  ts.release_redis(redis)
end

-- Generate authorization code from params
local function generate_code(client_data)
  return ts.sha1_digest(tostring(random.bytes(20, true)) .. "#code:" .. tostring(client_data.client_id))
end

local function store_code(client_data, params, code)
  local ok, err = persist_code(client_data, code)

  if not ok then
    ngx.header.content_type = "application/x-www-form-urlencoded"
    return ngx.redirect(params.redirect_uri .. "?error=server_error&error_description=code_storage_failed&state=" .. (params.state or "")), err
  end

  return ok, err
end

-- Get Authorization Code
local function get_code(client_data, params)
  local code = generate_code(client_data)

  local stored = store_code(client_data, params, code)

  if stored then
    send_code(client_data, code)
  end
end

-- Check valid state parameter sent
function _M.check_state(state)
  local redis
  local ok, err
  local client_data
  redis = ts.connect_redis()

  if redis then
    local tmp_data = ngx.ctx.service.id.."#tmp_data"..state
    ok, err = redis:hgetall(tmp_data)
    redis:del(tmp_data)

    if not ok then
      return ok, err
    end

    client_data = redis:array_to_hash(ok)
    ts.release_redis(redis)

    return client_data
  end
end

-- Returns the token to the client
local function send_token(token)
  ngx.header.content_type = "application/json; charset=utf-8"
  ngx.say(cjson.encode(token))
  ngx.exit(ngx.HTTP_OK)
end

-- Checks the authorization code being exchanged for an access token
-- This needs to be called within a minute of it being stored, as it expires and is deleted
local function check_code(params)
  local redis = ts.connect_redis()

  if redis then
    local ok, _ =  redis:hgetall("c:".. params.code)
      if ok[1] == nil then
      _M.respond_with_error(403, 'invalid_grant', 'Authorization Code is invalid or has expired')
      return
    end
    ts.release_redis(redis)
  else
    --TODO: how do we respond if we can't connect to redis? status code and msg
    _M.respond_with_error(500,'msg')
    return
  end
  return
end

-- Stores the token in 3scale.
local function store_token(params, token)
  local body = ts.build_query({ app_id = params.client_id, token = token.access_token, user_id = params.user_id, ttl = token.expires_in })
  -- TODO: Create a call for this ngx capture in the backend client
  local stored = ngx.location.capture( "/_threescale/oauth_store_token", {
    method = ngx.HTTP_POST, body = body, copy_all_vars = true, ctx = ngx.ctx } )
  stored.body = stored.body or stored.status
  return { status = stored.status , body = stored.body }
end

-- Request the token
local function request_token(params)
  local err
  local access_token = generate_access_token(params.client_id)

  local stored = store_token(params, access_token)

  if stored.status == 200 then
    send_token(access_token)
    return
  else
    err =  '{"error":"'..stored.body..'"}'
    _M.respond_with_error(stored.status, err)
    return
  end
end

-- Get the token from Redis
function _M:get_token(service)
  local ok, err
  local params = _M.extract_params()
  ngx.log(ngx.INFO, "params: " .. inspect(params))

  ok, err = _M.token_check_params(params)

  if not ok then
    _M.respond_with_error(400, err)
    return
  end

  if params.grant_type == "authorization_code" then
    check_code(params)
  elseif params.grant_type == "client_credentials" then
    ok = _M.check_credentials(service, params)
    if not ok then
      _M.respond_with_error(401, 'invalid_client')
      return
    end
  else
    -- TODO: something whent wrong, what do we return here?
    _M.respond_with_error(400, 'msg')
  end

  request_token(params)
end

function _M:authorize(service)
  local ok, err
  local params = ngx.req.get_uri_args()

  ok, err = _M.check_params(params)
  if not ok then
    _M.respond_with_error(400, err)
    return
  end

  ok = _M.check_credentials(service, params)
  if not ok then
    _M.respond_with_error(401, 'invalid_client')
    return
  end

  persist_nonce(service.id, params)

  local args = ts.build_query(params)
  local login_url = service.oauth_login_url or error('missing oauth login url')

  ngx.header.content_type = "application/x-www-form-urlencoded"
  return ngx.redirect(login_url .. "?" .. args)
end

function _M.callback()
  local ok, err
  local client_data
  local code

  local params = ngx.req.get_uri_args()

  if not params.state then
    _M.respond_with_error(400, "invalid_request")
    return
  end

  ok = _M.check_state(params.state)
  
  if not ok then
    -- TODO: Add debug message for ngx
    _M.respond_with_error(400, 'invalid_state')
    return
  end
  
  client_data = retrieve_client_data(ngx.ctx.service.id, params)

  if client_data.grant == 'code' then
    ok, err = get_code(client_data, params)
    if not ok then
      _M.redirect_with_error(client_data.redirect_uri, err, client_data.state)
      return
    end

    code = ok
    ngx.header.content_type = "application/x-www-form-urlencoded"
    return ngx.redirect( client_data.redirect_uri .. "?code="..code.."&state=" .. (client_data.state or ""))
  elseif client_data.grant == 'token' then
    request_token(client_data)
  else
  -- TODO: Add debug message for ngx
  -- TODO: where do we get the redirect_uri from unless the Authorization passes it back to us?
    _M.respond_with_error(400, 'invalid_state')
    return
  end
end

return _M