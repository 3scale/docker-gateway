local cjson = require 'cjson'
local ts = require 'threescale_utils'
local util = require 'util'
local split = util.string_split

-- As per RFC for Resource Owner Password flow: extract params from Authorization header and body
-- If implementation deviates from RFC, this function should be over-ridden
function extract_params()
  local params = {}
  local header_params = ngx.req.get_headers()

  params.authorization = {}

  if header_params['Authorization'] then
    params.authorization = split(ngx.decode_base64(split(header_params['Authorization']," ")[2]),":")
  end
  
  ngx.req.read_body()
  local body_params = ngx.req.get_post_args()
  
  params.client_id = params.authorization[1] or body_params.client_id
  params.client_secret = params.authorization[2] or body_params.client_secret
  
  params.grant_type = body_params.grant_type 
  params.user_id = body_params.user_id or body_params.username 
  params.password = body_params.password 

  if params.grant_type == "refresh_token" then
    params.refresh_token = body_params.refresh_token 
  end

  return params
end

-- Check valid credentials
function check_credentials(params)
  local res = check_client_credentials(params)
  return res.status == 200
end

-- Check valid params ( client_id / secret / redirect_url, whichever are sent) against 3scale
function check_client_credentials(params)
  local res = ngx.location.capture("/_threescale/check_credentials",
              { args = { app_id = params.client_id , app_key = params.client_secret , redirect_uri = params.redirect_uri  } })
  
  if res.status ~= 200 then   
    ngx.status = 401
    ngx.header.content_type = "application/json; charset=utf-8"
    ngx.print('{"error":"invalid_client"}')
    ngx.exit(ngx.HTTP_OK)
  end

  return { ["status"] = res.status, ["body"] = res.body }
end

-- Get the token from the OAuth Server
function get_token(params)
  local access_token_required_params = {'user_id', 'password', 'grant_type'}
  local refresh_token_required_params =  {'client_id', 'client_secret', 'grant_type', 'refresh_token'}
  
  local res = {}
  
  if (ts.required_params_present(access_token_required_params, params) and params['grant_type'] == 'password') or 
    (ts.required_params_present(refresh_token_required_params, params) and params['grant_type'] == 'refresh_token') then
    res = request_token(params)
  else
    res = { ["status"] = 403, ["body"] = '{"error": "invalid_request"}' }
  end

  if res.status ~= 200 then
    ngx.status = res.status
    ngx.header.content_type = "application/json; charset=utf-8"
    ngx.print(res.body)
    ngx.exit(ngx.HTTP_FORBIDDEN)
  else
    local token = parse_token(res.body)
    local stored = store_token(params, token)

    if stored.status ~= 200 then
      ngx.say(stored.body)
      ngx.status = stored.status
      ngx.exit(ngx.HTTP_OK)
    else
      send_token(token)
    end
  end
end

-- Calls the token endpoint to request a token
function request_token()
  local res = ngx.location.capture("/_oauth/token", { method = ngx.HTTP_POST, copy_all_vars = true })
  return { ["status"] = res.status, ["body"] = res.body }
end

-- Parses the token - in this case we assume a json encoded token. This function may be overwritten to parse different token formats.
function parse_token(body)
  local token = cjson.decode(body)
  ngx.log(ngx.ERR, '[notice]: token returned by RH-SSO: ')
  ngx.log(ngx.ERR, ts.dump(token))
  
  local jwt = token.access_token
  local header, access_token, signature = jwt:match("([^.]+).([^.]+).([^.]+)")
  local payload = cjson.decode(ngx.decode_base64(access_token))
  local realm_access = payload["realm_access"]

  ngx.log(ngx.ERR, '[notice]: realm_access: ')
  ngx.log(ngx.ERR, ts.dump(realm_access))

  local threescale_token = {
    jwt = jwt,
    access_token = access_token,
    expires_in = token.expires_in,
    token_type = token.token_type,
    refresh_token = token.refresh_token,
    refresh_expires_in = 1800
  }

  return threescale_token
end

-- Stores the token in 3scale. You can change the default ttl value of 604800 seconds (7 days) to your desired ttl.
function store_token(params, token)
  local body = ts.build_query({ app_id = params.client_id, token = token.access_token, user_id = params.user_id, ttl = token.expires_in or "604800" })
  local stored = ngx.location.capture( "/_threescale/oauth_store_token", { method = ngx.HTTP_POST, body = body } )
  stored.body = stored.body or stored.status
  return { ["status"] = stored.status , ["body"] = stored.body }
end

-- Returns the token to the client
function send_token(token)
  ngx.header.content_type = "application/json; charset=utf-8"
  ngx.say(cjson.encode(token))
  ngx.exit(ngx.HTTP_OK)
end

local params = extract_params()

local is_valid = check_credentials(params)

if is_valid then
  get_token(params)
end