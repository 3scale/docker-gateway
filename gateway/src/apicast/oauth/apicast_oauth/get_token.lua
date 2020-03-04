local cjson = require 'cjson'
local ts = require 'apicast.threescale_utils'
local re = require 'ngx.re'
local env = require 'resty.env'
local backend_client = require('apicast.backend_client')
local http_ng_resty = require('resty.http_ng.backend.resty')
local tonumber = tonumber

local oauth_tokens_default_ttl = 604800 -- 7 days

-- As per RFC for Authorization Code flow: extract params from Authorization header and body
-- If implementation deviates from RFC, this function should be over-ridden
local function extract_params()
  local params = {}
  local header_params = ngx.req.get_headers()

  params.authorization = {}

  if header_params['Authorization'] then
    params.authorization = re.split(ngx.decode_base64(re.split(header_params['Authorization']," ", 'oj')[2]),":", 'oj')
  end

  -- TODO: exit with 400 if the request is GET
  ngx.req.read_body()
  local body_params = ngx.req.get_post_args()

  params.client_id = params.authorization[1] or body_params.client_id
  params.client_secret = params.authorization[2] or body_params.client_secret

  params.grant_type = body_params.grant_type
  params.code = body_params.code
  params.redirect_uri = body_params.redirect_uri or body_params.redirect_url

  return params
end

local function oauth_tokens_ttl()
  return tonumber(env.get('APICAST_OAUTH_TOKENS_TTL')) or oauth_tokens_default_ttl
end

-- Returns the access token (stored in redis) for the client identified by the id
-- This needs to be called within a minute of it being stored, as it expires and is deleted
local function request_token(params)
  local red = ts.connect_redis()
  local ok, _ =  red:hgetall("c:".. params.code)

  if ok[1] == nil then
    return { ["status"] = 403, ["body"] = '{"error": "expired_code"}' }
  else
    local client_data = red:array_to_hash(ok)
    params.user_id = client_data.user_id
    if params.code == client_data.code then
      return { ["status"] = 200,
               ["body"] = { ["access_token"] = client_data.access_token,
                            ["token_type"] = "bearer",
                            ["expires_in"] = oauth_tokens_ttl() } }
    else
      return { ["status"] = 403, ["body"] = '{"error": "invalid authorization code"}' }
    end
  end
end



-- Check valid params ( client_id / secret / redirect_url, whichever are sent) against 3scale
local function check_client_credentials(service, params)
  local backend = assert(backend_client:new(service, http_ng_resty), 'missing backend')
  local res = backend:authorize({ app_id = params.client_id, app_key = params.client_secret, redirect_uri = params.redirect_uri })

  ngx.log(ngx.INFO, "[oauth] Checking client credentials, status: ", res.status, " body: ", res.body)

  if res.status == 200 and
      ts.match_xml_element(res.body, 'key', params.client_secret) and
      ts.match_xml_element(res.body, 'authorized', true) then
    return { ["status"] = res.status, ["body"] = res.body }
  else
    ngx.status = 401
    ngx.header.content_type = "application/json; charset=utf-8"
    ngx.print('{"error":"invalid_client"}')
    ngx.exit(ngx.HTTP_OK)
  end
end


-- Returns the token to the client
local function send_token(token)
  ngx.header.content_type = "application/json; charset=utf-8"
  ngx.say(cjson.encode(token))
  ngx.exit(ngx.HTTP_OK)
end

-- Check valid credentials
local function check_credentials(params)
  local res = check_client_credentials(ngx.ctx.service, params)
  return res.status == 200
end

-- Stores the token in 3scale.
local function store_token(service, params, token)
  local backend = assert(backend_client:new(service, http_ng_resty), 'missing backend')
  local res = assert(backend:store_oauth_token({ app_id = params.client_id, token = token.access_token, user_id = params.user_id, ttl = token.expires_in }))

  return { status = res.status , body = res.body or res.status }
end


-- Get the token from Redis
local function get_token(params)
  local required_params = {'client_id', 'client_secret', 'grant_type', 'code', 'redirect_uri'}

  local res

  if ts.required_params_present(required_params, params) and params['grant_type'] == 'authorization_code'  then
    res = request_token(params)
  else
    res = { ["status"] = 403, ["body"] = '{"error": "invalid_request"}' }
  end

  if res.status == 200 then
    local token = res.body
    local stored = store_token(ngx.ctx.service, params, token)

    if stored.status == 200 then
      send_token(token)
    else
      ngx.status = stored.status
      ngx.say('{"error":"'..stored.body..'"}')
      ngx.exit(stored.status)
    end
  else
    ngx.status = res.status
    ngx.header.content_type = "application/json; charset=utf-8"
    ngx.print(res.body)
    ngx.exit(ngx.HTTP_FORBIDDEN)
  end
end

local _M = {
  VERSION = '0.0.1'
}

function _M.call()
  local params = extract_params()

  local is_valid = check_credentials(params)

  if is_valid then
    get_token(params)
  end
end

return _M

