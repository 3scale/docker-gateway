local random = require 'resty.random'
local ts = require 'threescale_utils'
local inspect = require 'inspect'

-- returns a unique string for the client_id. it will be short lived
local function nonce(client_id)
  return ts.sha1_digest(tostring(random.bytes(20, true)) .. "#login:" .. client_id)
end

local function generate_access_token(client_id)
  return ts.sha1_digest(tostring(random.bytes(20, true)) .. client_id)
end

-- As per RFC for Authorization Code flow: extract params from request uri
-- If implementation deviates from RFC, this function should be over-ridden
local function extract_params()
  local params = {}
  local uri_params = ngx.req.get_uri_args()

  params.response_type = uri_params.response_type
  params.client_id = uri_params.client_id
  params.redirect_uri = uri_params.redirect_uri
  params.scope =  uri_params.scope
  params.state = uri_params.state

  ngx.log(0, inspect(params))
  return params
end

local function persist_nonce(service_id, params)
  local n = nonce(params.client_id)
  params.state = n

  local red = ts.connect_redis()
  local pre_token = generate_access_token(params.client_id)
  params.tok = pre_token

  local ok, err = red:hmset(service_id .. "#tmp_data:".. n,
    {client_id = params.client_id,
      redirect_uri = params.redirect_uri,
      plan_id = params.scope,
      access_token = pre_token})

  if not ok then
    ts.error(ts.dump(err))
  end

  return n, err
end

-- redirects_to the authorization url of the API provider with a secret
-- 'state' which will be used when the form redirects the user back to
-- this server.
local function redirect_to_auth(params)
  local service = ngx.ctx.service

  if params.error then
    ngx.log(ngx.DEBUG, 'oauth params error: ' .. tostring(params.error))
  else
    persist_nonce(service.id, params)
  end

  local args = ts.build_query(params)
  local login_url = service.oauth_login_url or error('missing oauth login url')

  ngx.header.content_type = "application/x-www-form-urlencoded"
  return ngx.redirect(login_url .. "?" .. args)
end

-- Authorizes the client for the given scope
local function authorize(params)
  local required_params = {'client_id', 'redirect_uri', 'response_type', 'scope'}

  if params["response_type"] ~= 'code' then
    params.error = "unsupported_response_type"
  elseif not ts.required_params_present(required_params, params) then
    params.error = "invalid_request"
  end

  redirect_to_auth(params)
end


-- Check valid params ( client_id / secret / redirect_url, whichever are sent) against 3scale
local function check_client_credentials(params)
  local res = ngx.location.capture("/_threescale/check_credentials",
    {
      args = {
        app_id = params.client_id,
        app_key = params.client_secret,
        redirect_uri = params.redirect_uri
      },
      copy_all_vars = true,
      ctx = ngx.ctx
    })

  ngx.log(0, inspect(res))

  if res.status == 200 then
    return { ["status"] = res.status, ["body"] = res.body }
  else
    params.error = "invalid_client"
    redirect_to_auth(params)
  end
end

-- Check valid credentials
local function check_credentials(params)
  local res = check_client_credentials(params)
  return res.status == 200
end


local _M = {
  VERSION = '0.0.1'
}

function _M.call()
  local params = extract_params()
  local is_valid = check_credentials(params)

  if is_valid then
    ngx.log(ngx.DEBUG, 'oauth params valid')
    authorize(params)
  else
    ngx.log(ngx.DEBUG, 'oauth params invalid')
    params.error = "invalid_client"
    redirect_to_auth(params)
  end
end

_M.persist_nonce = persist_nonce

return _M
