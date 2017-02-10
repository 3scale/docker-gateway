local cjson = require 'cjson'
local env = require 'resty.env'
local custom_config = env.get('APICAST_CUSTOM_CONFIG')
local configuration_parser = require 'configuration_parser'
local configuration_store = require 'configuration_store'

local oauth = require 'oauth'
local resty_url = require 'resty.url'

local assert = assert
local type = type
local next = next
local insert = table.insert

local concat = table.concat
local gsub = string.gsub
local tonumber = tonumber
local setmetatable = setmetatable
local exit = ngx.exit
local encode_args = ngx.encode_args
local resty_resolver = require 'resty.resolver'
local dns_resolver = require 'resty.resolver.dns'
local newrelic = require('resty.newrelic')
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
  if not configuration or not configuration.find_by_host then return nil, 'not initialized' end

  local hosts = configuration:find_by_host(host)

  return next(hosts) and true
end

_M.init = function(config) return _M.configure(_M, config) end

-- Error Codes
local function error_no_credentials(service)
  ngx.log(ngx.INFO, 'no credentials provided for service ', service.id)
  ngx.var.cached_key = nil
  ngx.status = service.auth_missing_status
  ngx.header.content_type = service.auth_missing_headers
  ngx.print(service.error_auth_missing)
  ngx.exit(ngx.HTTP_OK)
end

local function error_authorization_failed(service)
  ngx.log(ngx.INFO, 'authorization failed for service ', service.id)
  ngx.var.cached_key = nil
  ngx.status = service.auth_failed_status
  ngx.header.content_type = service.auth_failed_headers
  ngx.print(service.error_auth_failed)
  ngx.exit(ngx.HTTP_OK)
end

local function error_no_match(service)
  ngx.log(ngx.INFO, 'no rules matched for service ', service.id)
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

local function get_debug_value(service)
  return ngx.var.http_x_3scale_debug == service.backend_authentication.value
end

local function find_service_strict(self, host)
  local found
  local services = self.configuration:find_by_host(host)

  for s=1, #services do
    local service = services[s]
    local hosts = service.hosts or {}

    for h=1, #hosts do
      if hosts[h] == host then
        found = service
        break
      end
    end
    if found then break end
  end

  return found or ngx.log(ngx.ERR, 'service not found for host ', host)
end

local function find_service_cascade(self, host)
  local found
  local request = ngx.var.request
  local services = self.configuration:find_by_host(host)

  for s=1, #services do
    local service = services[s]
    local hosts = service.hosts or {}

    for h=1, #hosts do
      if hosts[h] == host then
        local name = service.system_name or service.id
        ngx.log(ngx.DEBUG, 'service ', name, ' matched host ', hosts[h])
        local usage, matched_patterns = service:extract_usage(request)

        if next(usage) and matched_patterns ~= '' then
          ngx.log(ngx.DEBUG, 'service ', name, ' matched patterns ', matched_patterns)
          found = service
          break
        end
      end
    end
    if found then break end
  end

  return found or find_service_strict(self, host)
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
    local nr_transaction_id = ngx.ctx.nr_transaction_id
    local previous_real_url = ngx.var.real_url
    ngx.log(ngx.DEBUG, '[ctx] copying backend_upstream of size: ', #backend_upstream)
    local http_get_segment_id = newrelic.begin_external_segment(
      nr_transaction_id, newrelic.NEWRELIC_ROOT_SEGMENT, ngx.var.backend_endpoint .. url, 'GET')
    local res = ngx.location.capture(assert(url), {
      share_all_vars = true,
      ctx = {
        backend_upstream = backend_upstream,
        nr_transaction_id = nr_transaction_id
      }
    })
    newrelic.end_segment(nr_transaction_id, http_get_segment_id)

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
  local cached_key = ngx.var.cached_key .. ":" .. ngx.var.usage
  local access_tokens = assert(ngx.shared.api_keys, 'missing shared dictionary: api_keys')
  local is_known = access_tokens:get(cached_key)

  if is_known == 200 then
    ngx.log(ngx.DEBUG, 'apicast cache hit key: ', cached_key)
    ngx.var.cached_key = cached_key
  else
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
  -- NYI: return to lower frame
  local cached_key = ngx.var.cached_key .. ":" .. ngx.var.usage
  local api_keys = ngx.shared.api_keys
  local is_known = api_keys and api_keys:get(cached_key)

  if is_known == 200 then
    ngx.log(ngx.DEBUG, 'apicast cache hit key: ', cached_key)
    ngx.var.cached_key = cached_key
  else
    ngx.log(ngx.INFO, 'apicast cache miss key: ', cached_key)
    local res = http.get("/threescale_authrep")

    ngx.log(ngx.DEBUG, '[backend] response status: ', res.status, ' body: ', res.body)

    if res.status == 200 then
      if api_keys then
        ngx.log(ngx.INFO, 'apicast cache write key: ', cached_key)
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
  ngx.var.service_id = service.id
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

function _M.set_upstream(service)
  local upstream = _M.get_upstream(service)

  local nr_transaction_id = ngx.ctx.nr_transaction_id
  local resolver_get_servers_segment_id = newrelic.begin_datastore_segment(
    nr_transaction_id, newrelic.NEWRELIC_ROOT_SEGMENT, 'resolver', 'get_upstream_servers')

  ngx.ctx.dns = dns_resolver:new{ nameservers = resty_resolver.nameservers() }
  ngx.ctx.resolver = resty_resolver.new(ngx.ctx.dns)
  ngx.ctx.upstream = ngx.ctx.resolver:get_servers(upstream.server, { port = upstream.port })
  newrelic.end_segment(nr_transaction_id, resolver_get_servers_segment_id)

  ngx.var.proxy_pass = upstream.uri
  ngx.req.set_header('Host', upstream.host or ngx.var.host)
end

function _M:set_backend_upstream(service)
  service = service or ngx.ctx.service

  ngx.var.backend_authentication_type = service.backend_authentication.type
  ngx.var.backend_authentication_value = service.backend_authentication.value
  ngx.var.backend_host = service.backend.host or ngx.var.backend_host

  ngx.var.version = self.configuration.version

  -- set backend
  local url = resty_url.split(service.backend.endpoint or ngx.var.backend_endpoint)
  local scheme, _, _, server, port, path =
    url[1], url[2], url[3], url[4], url[5] or resty_url.default_port(url[1]), url[6] or ''

  local nr_transaction_id = ngx.ctx.nr_transaction_id
  local resolver_get_servers_segment_id = newrelic.begin_datastore_segment(
    nr_transaction_id, newrelic.NEWRELIC_ROOT_SEGMENT, 'resolver', 'get_backend_servers')

  ngx.ctx.dns = ngx.ctx.dns or dns_resolver:new{ nameservers = resty_resolver.nameservers() }
  ngx.ctx.resolver = ngx.ctx.resolver or resty_resolver.new(ngx.ctx.dns)

  local backend_upstream, err = ngx.ctx.resolver:get_servers(server, { port = port or nil })

  newrelic.end_segment(nr_transaction_id, resolver_get_servers_segment_id)

  ngx.log(ngx.DEBUG, '[resolver] resolved backend upstream: ', #backend_upstream)
  ngx.ctx.backend_upstream = backend_upstream

  ngx.var.backend_endpoint = scheme .. '://backend_upstream' .. path

end

function _M:call(host)
  host = host or ngx.var.host
  local service = ngx.ctx.service or self.set_service(host)

  self:set_backend_upstream(service)

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

  if ngx.status == 403  then
    ngx.say("Throttling due to too many requests")
    ngx.exit(403)
  end

  local request = ngx.var.request -- NYI: return to lower frame

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

  local _, matched_patterns, params = service:extract_usage(request)
  local usage = encode_args(params)

  -- remove integer keys for serialization
  -- as ngx.encode_args can't serialize integer keys
  for i=1,#credentials do
    credentials[i] = nil
  end

  credentials = encode_args(credentials)

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

function _M:post_action()

  local nr_transaction_id = ngx.var.nr_transaction_id
  local upstream_transaction_id = tonumber(ngx.var.upstream_transaction_id)

  if nr_transaction_id and upstream_transaction_id > 0 then
    newrelic.end_segment(nr_transaction_id, upstream_transaction_id)
  end

  local cached_key = ngx.var.cached_key

  if cached_key and cached_key ~= "null" then
    ngx.log(ngx.INFO, '[async] reporting to backend asynchronously, cached_key: ', cached_key)

    local service_id = ngx.var.service_id
    local service = ngx.ctx.service or self.configuration:find_by_id(service_id)
    self:set_backend_upstream(service)

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
      ngx.log(ngx.DEBUG, 'executing custom config ', custom_config)
      c.setup(_M)
    else
      ngx.log(ngx.ERR, 'failed to load custom config ', custom_config, ' because it does not return table with function setup')
    end
  else
    ngx.log(ngx.ERR, 'failed to load custom config ', custom_config, ' with ', c)
  end
end

return _M
