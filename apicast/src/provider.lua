-- provider_key: <%= provider_key %> --
-- -*- mode: lua; -*-
-- Generated on: <%= Time.now %> --
-- Version:
-- Error Messages per service

local cjson = require 'cjson'
local custom_config = os.getenv('APICAST_CUSTOM_CONFIG')
local configuration = require 'configuration'
local inspect = require 'inspect'
local oauth = require 'oauth'
local util = require 'util'

local type = type
local pairs = pairs
local ipairs = ipairs
local insert = table.insert
local lower = string.lower

local concat = table.concat
local tostring = tostring
local format = string.format
local gsub = string.gsub
local unpack = unpack

local split = util.string_split

local resty_resolver = require 'resty.resolver'
local dns_resolver = require 'resty.resolver.dns'

local response_codes = util.env_enabled('APICAST_RESPONSE_CODES')
local request_logs = util.env_enabled('APICAST_REQUEST_LOGS')

local _M = {
  -- FIXME: this is really bad idea, this file is shared across all requests,
  -- so that means sharing something in this module would be sharing it acros all requests
  -- and in multi-tenant environment that would mean leaking information
  configuration = {}
}

function _M.configure(contents)
  local config, err = configuration.parse(contents)

  if err then
    ngx.log(ngx.WARN, 'not configured: ', err)
    return nil, err
  end

  _M.contents = configuration.encode(contents)

  if config then
    _M.configured = true
    _M.configuration = config
    _M.services = config.services or {} -- for compatibility reasons
    return config
  else
    _M.configured = false
    _M.services = false
  end
end

function _M.init(config)
  math.randomseed(ngx.now())
  -- First calls to math.random after a randomseed tend to be similar; discard them
  for _=1,3 do math.random() end

  return _M.configure(config)
end

-- Error Codes
local function error_no_credentials(service)
  ngx.log(ngx.INFO, 'no credentials provided for service ' .. tostring(service.id))
  ngx.var.cached_key = nil
  ngx.status = service.auth_missing_status
  ngx.header.content_type = service.auth_missing_headers
  ngx.print(service.error_auth_missing)
  ngx.exit(ngx.HTTP_OK)
end

local function error_authorization_failed(service)
  ngx.log(ngx.INFO, 'authorization failed for service ' .. tostring(service.id))
  ngx.var.cached_key = nil
  ngx.status = service.auth_failed_status
  ngx.header.content_type = service.auth_failed_headers
  ngx.print(service.error_auth_failed)
  ngx.exit(ngx.HTTP_OK)
end

local function error_no_match(service)
  ngx.log(ngx.INFO, 'no rules matched for service ' .. tostring(service.id))
  ngx.var.cached_key = nil
  ngx.status = service.no_match_status
  ngx.header.content_type = service.no_match_headers
  ngx.print(service.error_no_match)
  ngx.exit(ngx.HTTP_OK)
end

local function error_service_not_found(host)
  ngx.status = 404
  ngx.print('')
  ngx.log(ngx.WARN, 'could not find service for host: ', host)
  ngx.exit(ngx.status)
end
-- End Error Codes

-- Aux function to split a string

local function first_values(a)
  local r = {}
  for k,v in pairs(a) do
    if type(v) == "table" then
      r[lower(k)] = v[1] -- TODO: use metatable to convert all access to lowercase
    else
      r[lower(k)] = v
    end
  end
  return r
end

local function build_querystring_formatter(fmt)
  return function (query)
    local function kvmap(f, t)
      local res = {}
      for k, v in pairs(t) do
        insert(res, f(k, v))
      end
      return res
    end

    return concat(kvmap(function(k,v) return format(fmt, k, v) end, query or {}), "&")
  end
end

local build_querystring = build_querystring_formatter("usage[%s]=%s")
local build_query = build_querystring_formatter("%s=%s")


--[[
  Authorization logic
]]--

local function get_debug_value()
  return ngx.var.http_x_3scale_debug == _M.configuration.debug_header
end

local function find_service_strict(host)
  for _,service in ipairs(_M.services or {}) do
    if type(host) == 'number' and service.id == host then
      return service
    end

    for _,_host in ipairs(service.hosts or {}) do
      if _host == host then
        return service
      end
    end
  end
  ngx.log(ngx.ERR, 'service not found for host ' .. host)
end

local function find_service_cascade(host)
  local request = ngx.var.request
  for _,service in ipairs(_M.services or {}) do
    for _,_host in ipairs(service.hosts or {}) do
      if _host == host then
        local name = service.system_name or service.id
        ngx.log(ngx.DEBUG, 'service ' .. name .. ' matched host ' .. _host)
        local usage, matched_patterns = service:extract_usage(request)

        if next(usage) and matched_patterns ~= '' then
          ngx.log(ngx.DEBUG, 'service ' .. name .. ' matched patterns ' .. matched_patterns)
          return service
        end
      end
    end
  end

  return find_service_strict(host)
end

if util.env_enabled('APICAST_PATH_ROUTING_ENABLED') then
  ngx.log(ngx.WARN, 'apicast experimental path routing enabled')
  _M.find_service = find_service_cascade
else
  _M.find_service = find_service_strict
end

local http = {
  get = function(url)
    ngx.log(ngx.INFO, '[http] requesting ' .. url)
    local backend_upstream = ngx.ctx.backend_upstream
    local previous_real_url = ngx.var.real_url
    ngx.log(ngx.DEBUG, '[ctx] copying backend_upstream of size: ', #backend_upstream)
    local res = ngx.location.capture(assert(url), { share_all_vars = true, ctx = { backend_upstream = backend_upstream } })

    local real_url = ngx.var.real_url

    if real_url ~= previous_real_url then
      ngx.log(ngx.INFO, '[http] ', real_url, ' (',tostring(res.status), ')')
    else
      ngx.log(ngx.INFO, '[http] status: ', tostring(res.status))
    end

    ngx.var.real_url = ''

    return res
  end
}

local function oauth_authrep(service)
  ngx.var.cached_key = ngx.var.cached_key .. ":" .. ngx.var.usage
  local access_tokens = assert(ngx.shared.api_keys, 'missing shared dictionary: api_keys')
  local is_known = access_tokens:get(ngx.var.cached_key)

  if is_known ~= 200 then
    local res = http.get("/threescale_oauth_authrep")

    -- IN HERE YOU DEFINE THE ERROR IF CREDENTIALS ARE PASSED, BUT THEY ARE NOT VALID
    if res.status ~= 200   then
      access_tokens:delete(ngx.var.cached_key)
      ngx.status = res.status
      ngx.header.content_type = "application/json"
      error_authorization_failed(service)
    else
      access_tokens:set(ngx.var.cached_key,200)
    end

    ngx.var.cached_key = nil
  end
end

local function authrep(service)
  local cached_key = ngx.var.cached_key .. ":" .. ngx.var.usage
  local api_keys = ngx.shared.api_keys
  local is_known = api_keys and api_keys:get(cached_key)

  if is_known == 200 then
    ngx.log(ngx.DEBUG, 'apicast cache hit key: ' .. cached_key)
    ngx.var.cached_key = cached_key
  else
    ngx.log(ngx.INFO, 'apicast cache miss key: ' .. cached_key)
    local res = http.get("/threescale_authrep")

    ngx.log(ngx.DEBUG, '[backend] response status: ' .. tostring(res.status) .. ' body: ' .. tostring(res.body))

    if res.status == 200 then
      if api_keys then
        ngx.log(ngx.INFO, 'apicast cache write key: ' .. tostring(cached_key))
        api_keys:set(cached_key, 200)
      end
    else -- TODO: proper error handling
      if api_keys then api_keys:delete(cached_key) end
      ngx.status = res.status
      ngx.header.content_type = "application/json"
      -- error_authorization_failed is an early return, so we have to reset cached_key to nil before -%>
      error_authorization_failed(service)
    end
    -- set this request_to_3scale_backend to nil to avoid doing the out of band authrep -%>
    ngx.var.cached_key = nil
  end
end

function _M.authorize(backend_version, service)
  if backend_version == 'oauth' then
    oauth_authrep(service)
  else
    authrep(service)
  end
end

function _M.set_service(host)
  host = host or ngx.var.host
  local service = _M.find_service(host)

  if not service then
    error_service_not_found(host)
  end

  ngx.ctx.service = service
end

function _M.set_upstream()
  local service = ngx.ctx.service

  -- The default values are only for tests. We need to set at least the scheme.
  local scheme, _, _, host, port, path =
    unpack(configuration.url(service.api_backend) or { 'http' })

  ngx.ctx.dns = dns_resolver:new{ nameservers = resty_resolver.nameservers() }
  ngx.ctx.resolver = resty_resolver.new(ngx.ctx.dns)
  ngx.var.proxy_pass = scheme .. '://upstream' .. (path or '')
  ngx.req.set_header('Host', service.hostname_rewrite or host or ngx.var.host)
  ngx.ctx.upstream = ngx.ctx.resolver:get_servers(host, { port = port })
end

function _M.call(host)
  host = host or ngx.var.host
  if not ngx.ctx.service then
    _M.set_service(host)
  end

  local service = ngx.ctx.service

  ngx.var.backend_authentication_type = service.backend_authentication.type
  ngx.var.backend_authentication_value = service.backend_authentication.value
  ngx.var.backend_host = service.backend.host or ngx.var.backend_host

  ngx.var.service_id = tostring(service.id)

  ngx.var.version = _M.configuration.version

  -- set backend
  local scheme, _, _, server, port, path = unpack(configuration.url(service.backend.endpoint or ngx.var.backend_endpoint))

  if not port then
    if scheme == 'http' then
      port = 80
    elseif scheme == 'https' then
      port = 443
    end
  end

  ngx.ctx.dns = ngx.ctx.dns or dns_resolver:new{ nameservers = resty_resolver.nameservers() }
  ngx.ctx.resolver = ngx.ctx.resolver or resty_resolver.new(ngx.ctx.dns)

  local backend_upstream = ngx.ctx.resolver:get_servers(server, { port = port or nil })
  ngx.log(ngx.DEBUG, '[resolver] resolved backend upstream: ', #backend_upstream)
  ngx.ctx.backend_upstream = backend_upstream
  ngx.var.backend_endpoint = scheme .. '://backend_upstream' .. (path or '')

  if service.backend_version == 'oauth' then
    local f, params = oauth.call()

    if f then
      ngx.log(ngx.DEBUG, 'apicast oauth flow')
      return function() return f(params) end
    end
  end

  return function()
    -- call access phase
    return _M.access(service)
  end
end

function _M.access(service)
  local scheme, _, _, host, port, path = unpack(configuration.url(service.api_backend) or {})
  local backend_version = service.backend_version
  local params = {}
  local usage
  local matched_patterns

  if ngx.status == 403  then
    ngx.say("Throttling due to too many requests")
    ngx.exit(403)
  end

  ngx.var.secret_token = service.secret_token

  local request = ngx.var.request
  local method =  split(request, " ")[1]

  local auth_params, cached_key = service:extract_credentials(method)

  if not cached_key then 
    return error_no_credentials(service)
  end

  usage, matched_patterns = service:extract_usage(request)

  ngx.log(ngx.INFO, inspect{usage, matched_patterns})
  
  ngx.var.access_token = auth_params.access_token
  ngx.var.cached_key = cached_key
  ngx.var.credentials = build_query(auth_params)
  ngx.var.usage = build_querystring(usage)

  -- WHAT TO DO IF NO USAGE CAN BE DERIVED FROM THE REQUEST.
  if ngx.var.usage == '' then
    ngx.header["X-3scale-matched-rules"] = ''
    return error_no_match(service)
  end

  if get_debug_value() then
    ngx.header["X-3scale-matched-rules"] = matched_patterns
    ngx.header["X-3scale-credentials"]   = ngx.var.credentials
    ngx.header["X-3scale-usage"]         = ngx.var.usage
    ngx.header["X-3scale-hostname"]      = ngx.var.hostname
  end

  _M.authorize(backend_version, service)

  -- set upstream
  ngx.var.proxy_pass = scheme .. '://upstream' .. (path or '')
  ngx.req.set_header('Host', service.hostname_rewrite or host or ngx.var.host)

  ngx.ctx.upstream = ngx.ctx.resolver:get_servers(host, { port = port })
end


local function request_logs_encoded_data()
  local request_log = {}

  if request_logs then
    local method, path, headers = ngx.req.get_method(), ngx.var.request_uri, ngx.req.get_headers()

    local req = cjson.encode{ method=method, path=path, headers=headers }
    local resp = cjson.encode{ body = ngx.var.resp_body, headers = cjson.decode(ngx.var.resp_headers) }

    request_log["log[request]"] = req
    request_log["log[response]"] = resp
  end

  if response_codes then
    request_log["log[code]"] = ngx.var.status
  end

  return ngx.escape_uri(ngx.encode_args(request_log))
end

function _M.post_action()
  local service_id = tonumber(ngx.var.service_id, 10)

  _M.call(service_id) -- initialize resolver and get backend upstream peers

  local cached_key = ngx.var.cached_key
  local service = ngx.ctx.service

  if cached_key and cached_key ~= "null" then
    ngx.log(ngx.INFO, '[async] reporting to backend asynchronously')

    local auth_uri = service.backend_version == 'oauth' and 'threescale_oauth_authrep' or 'threescale_authrep'
    local res = http.get("/".. auth_uri .."?log=" .. request_logs_encoded_data())

    if res.status ~= 200 then
      local api_keys = ngx.shared.api_keys

      if api_keys then
        ngx.log(ngx.NOTICE, 'apicast cache delete key: ' .. cached_key .. ' cause status ' .. tostring(res.status))
        api_keys:delete(cached_key)
      else
        ngx.log(ngx.ALERT, 'apicast cache error missing shared memory zone api_keys')
      end
    end
  else
    ngx.log(ngx.INFO, '[async] skipping after action, no cached key')
  end

  ngx.exit(ngx.HTTP_OK)
end

if custom_config then
  local path = package.path
  local module = gsub(custom_config, '%.lua$', '') -- strip .lua from end of the file
  package.path = package.path .. ';' .. ngx.config.prefix() .. '?.lua;'
  local ok, c = pcall(function() return require(module) end)
  package.path = path

  if ok then
    if type(c) == 'table' and type(c.setup) == 'function' then
      ngx.log(ngx.DEBUG, 'executing custom config ' .. custom_config)
      c.setup(_M)
    else
      ngx.log(ngx.ERR, 'failed to load custom config ' .. tostring(custom_config) .. ' because it does not return table with function setup')
    end
  else
    ngx.log(ngx.ERR, 'failed to load custom config ' .. tostring(custom_config) .. ' with ' .. tostring(c))
  end
end

return _M

-- END OF SCRIPT
