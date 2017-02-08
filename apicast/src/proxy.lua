local cjson = require 'cjson'
local env = require 'resty.env'
local custom_config = env.get('APICAST_CUSTOM_CONFIG')
local configuration_parser = require 'configuration_parser'
local configuration_store = require 'configuration_store'

local inspect = require 'inspect'
local oauth = require 'oauth'
local resty_url = require 'resty.url'

local assert = assert
local type = type
local pairs = pairs
local ipairs = ipairs
local next = next
local insert = table.insert

local concat = table.concat
local tostring = tostring
local format = string.format
local gsub = string.gsub
local tonumber = tonumber
local setmetatable = setmetatable
local exit = ngx.exit
local resty_resolver = require 'resty.resolver'
local dns_resolver = require 'resty.resolver.dns'
local empty = {}

local response_codes = env.enabled('APICAST_RESPONSE_CODES')
local request_logs = env.enabled('APICAST_REQUEST_LOGS')

local _M = {
  -- FIXME: this is really bad idea, this file is shared across all requests,
  -- so that means sharing something in this module would be sharing it acros all requests
  -- and in multi-tenant environment that would mean leaking information
  configuration = configuration_store.new()
}

local mt = {
  __index = _M
}

function _M.new(configuration)
  return setmetatable({
    configuration = configuration
  }, mt)
end

function _M:configure(contents)
  if self and not contents then contents = self end

  local config, err = configuration_parser.parse(contents)

  if err then
    ngx.log(ngx.WARN, 'not configured: ', err)
    ngx.log(ngx.DEBUG, 'config: ', contents)

    return nil, err
  end

  -- FIXME: using global configuration interface
  local configuration = self.configuration or _M.configuration

  if config then
    return configuration:store(config)
  end
end

function _M:configured(host)
  if not self then return nil, 'not initialized' end
  local configuration = self.configuration
  if not configuration or not configuration.find then return nil, 'not initialized' end

  local hosts = configuration:find(host)

  return next(hosts) and true
end

_M.init = function(config) return _M.configure(_M, config) end

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

local function build_querystring_formatter(fmt)
  return function (query)
    local function kvmap(f, t)
      local res = {}
      for k, v in pairs(t) do
        insert(res, f(k, v))
      end
      return res
    end

    return concat(kvmap(function(k,v) return format(fmt, k, tostring(v)) end, query or {}), "&")
  end
end

local build_querystring = build_querystring_formatter("usage[%s]=%s")
local build_query = build_querystring_formatter("%s=%s")

local function get_debug_value(service)
  return ngx.var.http_x_3scale_debug == service.backend_authentication.value
end

local function find_service_strict(self, host)
  for _,service in pairs(self.configuration:find(host)) do
    if service.id == host then
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

local function find_service_cascade(self, host)
  local request = ngx.var.request
  for _,service in pairs(self.configuration:find(host)) do
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

if configuration_store.path_routing then
  ngx.log(ngx.WARN, 'apicast experimental path routing enabled')
  _M.find_service = find_service_cascade
else
  _M.find_service = find_service_strict
end

local http = {
  get = function(url)
    ngx.log(ngx.INFO, '[http] requesting ', url)
    local backend_upstream = ngx.ctx.backend_upstream
    local previous_real_url = ngx.var.real_url
    ngx.log(ngx.DEBUG, '[ctx] copying backend_upstream of size: ', #backend_upstream)
    local res = ngx.location.capture(assert(url), { share_all_vars = true, ctx = { backend_upstream = backend_upstream } })

    local real_url = ngx.var.real_url

    if real_url ~= previous_real_url then
      ngx.log(ngx.INFO, '[http] ', real_url, ' (',res.status, ')')
    else
      ngx.log(ngx.INFO, '[http] status: ', res.status)
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
  local service = _M:find_service(host)

  if not service then
    error_service_not_found(host)
  end

  ngx.ctx.service = service
  return service
end

function _M.get_upstream(service)
  service = service or ngx.ctx.service

  local url = resty_url.split(service.api_backend) or empty
  local scheme = url[1] or 'http'
  local host, port, path =
    url[4], url[5] or resty_url.default_port(url[1]), url[6] or ''

  return {
    server = host,
    host = service.hostname_rewrite or host,
    uri  = scheme .. '://upstream' .. path,
    port = tonumber(port)
  }
end

function _M.set_upstream()
  local upstream = _M.get_upstream()

  ngx.ctx.dns = dns_resolver:new{ nameservers = resty_resolver.nameservers() }
  ngx.ctx.resolver = resty_resolver.new(ngx.ctx.dns)
  ngx.ctx.upstream = ngx.ctx.resolver:get_servers(upstream.server, { port = upstream.port })

  ngx.var.proxy_pass = upstream.uri
  ngx.req.set_header('Host', upstream.host or ngx.var.host)
end

function _M:call(host)
  host = host or ngx.var.host

  if not ngx.ctx.service then
    self.set_service(host)
  end

  local service = ngx.ctx.service

  ngx.var.backend_authentication_type = service.backend_authentication.type
  ngx.var.backend_authentication_value = service.backend_authentication.value
  ngx.var.backend_host = service.backend.host or ngx.var.backend_host

  ngx.var.service_id = service.id

  ngx.var.version = self.configuration.version

  -- set backend
  local url = resty_url.split(service.backend.endpoint or ngx.var.backend_endpoint)
  local scheme, _, _, server, port, path =
    url[1], url[2], url[3], url[4], url[5] or resty_url.default_port(url[1]), url[6] or ''

  ngx.ctx.dns = ngx.ctx.dns or dns_resolver:new{ nameservers = resty_resolver.nameservers() }
  ngx.ctx.resolver = ngx.ctx.resolver or resty_resolver.new(ngx.ctx.dns)

  local backend_upstream = ngx.ctx.resolver:get_servers(server, { port = port or nil })
  ngx.log(ngx.DEBUG, '[resolver] resolved backend upstream: ', #backend_upstream)
  ngx.ctx.backend_upstream = backend_upstream

  ngx.var.backend_endpoint = scheme .. '://backend_upstream' .. path

  if service.backend_version == 'oauth' then
    local f, params = oauth.call()

    if f then
      ngx.log(ngx.DEBUG, 'apicast oauth flow')
      return function() return f(params) end
    end
  end

  return function()
    -- call access phase
    return self:access(service)
  end
end

function _M:access(service)
  local backend_version = service.backend_version
  local usage
  local matched_patterns

  if ngx.status == 403  then
    ngx.say("Throttling due to too many requests")
    ngx.exit(403)
  end

  local request = ngx.var.request

  ngx.var.secret_token = service.secret_token

  local credentials, err = service:extract_credentials()

  if not credentials or #credentials == 0 then
    if err then
      ngx.log(ngx.WARN, "cannot get credentials: ", err)
    end
    return error_no_credentials(service)
  end

  insert(credentials, 1, service.id)
  ngx.var.cached_key = concat(credentials, ':')

  usage, matched_patterns = service:extract_usage(request)

  usage = build_querystring(usage)
  credentials = build_query(credentials)

  ngx.var.credentials = credentials
  ngx.var.usage = usage
  ngx.log(ngx.INFO, 'usage: ', usage, ' credentials: ', credentials)

  -- WHAT TO DO IF NO USAGE CAN BE DERIVED FROM THE REQUEST.
  if ngx.var.usage == '' then
    ngx.header["X-3scale-matched-rules"] = ''
    return error_no_match(service)
  end

  if get_debug_value(service) then
    ngx.header["X-3scale-matched-rules"] = matched_patterns
    ngx.header["X-3scale-credentials"]   = ngx.var.credentials
    ngx.header["X-3scale-usage"]         = ngx.var.usage
    ngx.header["X-3scale-hostname"]      = ngx.var.hostname
  end

  self.authorize(backend_version, service)
end


local function request_logs_encoded_data()
  local request_log = {}

  if not request_logs and not response_codes then
    return ''
  end

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
  local p = _M.new()
  ngx.ctx.proxy = p
  p:call(ngx.var.service_id) -- initialize resolver and get backend upstream peers

  local cached_key = ngx.var.cached_key
  local service = ngx.ctx.service

  if cached_key and cached_key ~= "null" then
    ngx.log(ngx.INFO, '[async] reporting to backend asynchronously')

    local auth_uri = service.backend_version == 'oauth' and 'threescale_oauth_authrep' or 'threescale_authrep'
    local res = http.get("/".. auth_uri .."?log=" .. request_logs_encoded_data())

    if res.status ~= 200 then
      local api_keys = ngx.shared.api_keys

      if api_keys then
        ngx.log(ngx.NOTICE, 'apicast cache delete key: ', cached_key, ' cause status ', res.status)
        api_keys:delete(cached_key)
      else
        ngx.log(ngx.ALERT, 'apicast cache error missing shared memory zone api_keys')
      end
    end
  else
    ngx.log(ngx.INFO, '[async] skipping after action, no cached key')
  end

  exit(ngx.HTTP_OK)
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
