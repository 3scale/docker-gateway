-- -*- mode: lua; -*-
-- Version:
-- Error Messages per service
local _M = {}

service_CHANGE_ME_SERVICE_ID = {
  error_auth_failed = 'Authentication failed',
  error_auth_missing = 'Authentication parameters missing',
  auth_failed_headers = 'text/plain; charset=us-ascii',
  auth_missing_headers = 'text/plain; charset=us-ascii',
  error_no_match = 'No Mapping Rule matched',
  no_match_headers = 'text/plain; charset=us-ascii',
  no_match_status = 404,
  auth_failed_status = 403,
  auth_missing_status = 403,
  secret_token = 'Shared_secret_sent_from_proxy_to_API_backend'
}


-- Logging Helpers
function show_table(a)
  for k,v in pairs(a) do
    local msg = ""
    msg = msg.. k
    if type(v) == "string" then
      msg = msg.. " => " .. v
    end
    ngx.log(0,msg)
  end
end

function log_message(str)
  ngx.log(0, str)
end

function log(content)
  if type(content) == "table" then
    show_table(content)
  else
    log_message(content)
  end
  newline()
end

function newline()
  ngx.log(0,"  ---   ")
end
-- End Logging Helpers

-- Error Codes
function error_no_credentials(service)
  ngx.status = service.auth_missing_status
  ngx.header.content_type = service.auth_missing_headers
  ngx.print(service.error_auth_missing)
  ngx.exit(ngx.HTTP_OK)
end

function error_authorization_failed(service)
  ngx.status = service.auth_failed_status
  ngx.header.content_type = service.auth_failed_headers
  ngx.print(service.error_auth_failed)
  ngx.exit(ngx.HTTP_OK)
end

function error_no_match(service)
  ngx.status = service.no_match_status
  ngx.header.content_type = service.no_match_headers
  ngx.print(service.error_no_match)
  ngx.exit(ngx.HTTP_OK)
end
-- End Error Codes

--[[
  Aux function to split a string
]]--

function string:split(delimiter)
  local result = { }
  local from = 1
  local delim_from, delim_to = string.find( self, delimiter, from )
  if delim_from == nil then return {self} end
  while delim_from do
    table.insert( result, string.sub( self, from , delim_from-1 ) )
    from = delim_to + 1
    delim_from, delim_to = string.find( self, delimiter, from )
  end
  table.insert( result, string.sub( self, from ) )
  return result
end

function first_values(a)
  r = {}
  for k,v in pairs(a) do
    if type(v) == "table" then
      r[k] = v[1]
    else
      r[k] = v
    end
  end
  return r
end

function set_or_inc(t, name, delta)
  return (t[name] or 0) + delta
end

function build_querystring(query)
  local qstr = ""

  for i,v in pairs(query) do
    qstr = qstr .. 'usage[' .. i .. ']' .. '=' .. v .. '&'
  end
  return string.sub(qstr, 0, #qstr-1)
end


---
-- Builds a query string from a table.
--
-- This is the inverse of <code>parse_query</code>.
-- @param query A dictionary table where <code>table['name']</code> =
-- <code>value</code>.
-- @return A query string (like <code>"name=value2&name=value2"</code>).
-----------------------------------------------------------------------------
function build_query(query)
  local qstr = ""

  for i,v in pairs(query) do
    qstr = qstr .. i .. '=' .. v .. '&'
  end
  return string.sub(qstr, 0, #qstr-1)
end

--[[

  Mapping between url path to 3scale methods. In here you must output the usage string encoded as a query_string param.
  Here there is an example of 2 resources (word, and sentence) and 3 methods. The complexity of this function depends
  on the level of control you want to apply. If you only want to report hits for any of your methods it would be as simple
  as this:

  function extract_usage(request)
    return "usage[hits]=1&"
  end

  In addition. You do not have to do this on LUA, you can do it straight from the nginx conf via the location. For instance:

  location ~ ^/v1/word {
		set $provider_key null;
		set $app_id null;
		set $app_key null;
		set $usage "usage[hits]=1&";

		access_by_lua_file /Users/solso/3scale/proxy/nginx_sentiment.lua;

		proxy_pass http://sentiment_backend;
		proxy_set_header  X-Real-IP  $remote_addr;
		proxy_set_header  Host  $host;
	}

	This is totally up to you. We prefer to keep the nginx conf as clean as possible. But you might already have declared
	the resources there, in this case, it's better to declare the $usage explicitly

]]--

matched_rules2 = ""

  function extract_usage_CHANGE_ME_SERVICE_ID(request)
  local t = string.split(request," ")
  local method = t[1]
  local q = string.split(t[2], "?")
  local path = q[1]
  local found = false
  local usage_t =  {}
  local m = ""
  local matched_rules = {}
  local params = {}

  local args = get_auth_params(nil, method)

  -- mapping rules go here, e.g
    local m =  ngx.re.match(path,[=[^/]=])
  if (m and method == "GET") then
     -- rule: / --
          
     table.insert(matched_rules, "/")

      usage_t["hits"] = set_or_inc(usage_t, "hits", 1)
      found = true
      end

  -- if there was no match, usage is set to nil and it will respond a 404, this behavior can be changed
  if found then
   matched_rules2 = table.concat(matched_rules, ", ")
   return build_querystring(usage_t)
  else
    return nil
  end
end

--[[
  Authorization logic
]]--

function get_auth_params(where, method)
  local params = {}
  if where == "headers" then
    params = ngx.req.get_headers()
  elseif method == "GET" then
    params = ngx.req.get_uri_args()
  else
    ngx.req.read_body()
    params = ngx.req.get_post_args()
  end
  return first_values(params)
end

function get_credentials_app_id_app_key(params, service)
  if params["app_id"] == nil or params["app_key"] == nil then
    error_no_credentials(service)
  end
end

function get_credentials_access_token(params, service)
  if params["access_token"] == nil and params["authorization"] == nil then -- TODO: check where the params come
    error_no_credentials(service)
  end
end

function get_credentials_user_key(params, service)
  if params["user_key"] == nil then
    error_no_credentials(service)
  end
end

function get_debug_value()
  local h = ngx.req.get_headers()
  if h["X-3scale-debug"] == 'CHANGE_ME_PROVIDER_KEY' then
    return true
  else
    return false
  end
end

function authorize(auth_strat, params, service)
  if auth_strat == 'oauth' then
    oauth(params, service)
  else
    authrep(params, service)
  end
end

function oauth(params, service)
  ngx.var.cached_key = ngx.var.cached_key .. ":" .. ngx.var.usage
  local access_tokens = ngx.shared.api_keys
  local is_known = access_tokens:get(ngx.var.cached_key)

  if is_known ~= 200 then
    local res = ngx.location.capture("/threescale_oauth_authrep", { share_all_vars = true })

    -- IN HERE YOU DEFINE THE ERROR IF CREDENTIALS ARE PASSED, BUT THEY ARE NOT VALID
  if res.status ~= 200   then
      access_tokens:delete(ngx.var.cached_key)
      ngx.status = res.status
      ngx.header.content_type = "application/json"
      ngx.var.cached_key = nil
      error_authorization_failed(service)
    else
      access_tokens:set(ngx.var.cached_key,200)
  end

    ngx.var.cached_key = nil
  end
end

function authrep(params, service)
  ngx.var.cached_key = ngx.var.cached_key .. ":" .. ngx.var.usage
  local api_keys = ngx.shared.api_keys
  local is_known = api_keys:get(ngx.var.cached_key)

  if is_known ~= 200 then
    local res = ngx.location.capture("/threescale_authrep", { share_all_vars = true })

    -- IN HERE YOU DEFINE THE ERROR IF CREDENTIALS ARE PASSED, BUT THEY ARE NOT VALID
    if res.status ~= 200 then
      -- remove the key, if it's not 200 let's go the slow route, to 3scale's backend
      api_keys:delete(ngx.var.cached_key)
      ngx.status = res.status
      ngx.header.content_type = "application/json"
            ngx.var.cached_key = nil
      error_authorization_failed(service)
    else
            api_keys:set(ngx.var.cached_key,200)
    end

        ngx.var.cached_key = nil
  end
end

function add_trans(usage)
  local us = usage:split("&")
  local ret = ""
  for i,v in ipairs(us) do
    ret =  ret .. "transactions[0][usage]" .. string.sub(v, 6) .. "&"
  end
  return string.sub(ret, 1, -2)
end


function _M.access()
local params = {}
local host = ngx.req.get_headers()["Host"]
local auth_strat = ""
local service = {}

  if ngx.status == 403  then
    ngx.say("Throttling due to too many requests")
    ngx.exit(403)
  end

if ngx.var.service_id == 'CHANGE_ME_SERVICE_ID' then
  local parameters = get_auth_params("CHANGE_ME_AUTH_PARAMS_LOCATION", string.split(ngx.var.request, " ")[1] )
  service = service_CHANGE_ME_SERVICE_ID --
  ngx.var.secret_token = service.secret_token

  -- Do this to remove token type, e.g Bearer from token
  -- params.access_token = string.split(parameters["authorization"], " ")[2]
  -- ngx.var.access_token = params.access_token

  ngx.var.access_token = parameters.access_token


  local authparams = {}
  authparams = ngx.req.get_headers()
  local accessToken = nil

  if authparams["Authorization"] then
      local m = ngx.re.match(authparams["Authorization"], "Bearer\\s(.+)")
      params.access_token = m[1]
  end 


  get_credentials_access_token(params , service_CHANGE_ME_SERVICE_ID)
  ngx.var.cached_key = "CHANGE_ME_SERVICE_ID" .. ":" .. params.access_token
  auth_strat = "oauth"
  ngx.var.service_id = "CHANGE_ME_SERVICE_ID"
  ngx.var.proxy_pass = "https://backend_CHANGE_ME_API_BACKEND"
  ngx.var.usage = extract_usage_CHANGE_ME_SERVICE_ID(ngx.var.request)
end

ngx.var.credentials = build_query(params)

-- if true then
--   log(ngx.var.app_id)
--   log(ngx.var.app_key)
--   log(ngx.var.usage)
-- end

-- WHAT TO DO IF NO USAGE CAN BE DERIVED FROM THE REQUEST.
if ngx.var.usage == nil then
  ngx.header["X-3scale-matched-rules"] = ''
  error_no_match(service)
end

if get_debug_value() then
  ngx.header["X-3scale-matched-rules"] = matched_rules2
  ngx.header["X-3scale-credentials"]   = ngx.var.credentials
  ngx.header["X-3scale-usage"]         = ngx.var.usage
  ngx.header["X-3scale-hostname"]      = ngx.var.hostname
end

-- this would be better with the whole authrep call, with user_id, and everything so that
-- it can be replayed if it's a cached response

authorize(auth_strat, params, service)

end


function _M.post_action_content()
  local method, path, headers = ngx.req.get_method(), ngx.var.request_uri, ngx.req.get_headers()

  local req = cjson.encode{method=method, path=path, headers=headers}
  local resp = cjson.encode{ body = ngx.var.resp_body, headers = cjson.decode(ngx.var.resp_headers)}

  local cached_key = ngx.var.cached_key
  if cached_key ~= nil and cached_key ~= "null" then
    local status_code = ngx.var.status
          local res1 = ngx.location.capture("/threescale_oauth_authrep?code=".. status_code .. "&req=" .. ngx.escape_uri(req) .. "&resp=" .. ngx.escape_uri(resp), { share_all_vars = true })
    if res1.status ~= 200 then
            local access_tokens = ngx.shared.api_keys
            access_tokens:delete(cached_key)
    end
  end

  ngx.exit(ngx.HTTP_OK)
end


return _M

-- END OF SCRIPT
