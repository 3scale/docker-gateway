local _M = {
  _VERSION = '0.01',
}

local len = string.len
local pairs = pairs
local type = type
local tostring = tostring
local next = next
local lower = string.lower
local insert = table.insert
local setmetatable = setmetatable
local null = ngx.null

local env = require 'resty.env'
local resty_url = require 'resty.url'
local util = require 'apicast.util'
local policy_chain = require 'apicast.policy_chain'
local mapping_rule = require 'apicast.mapping_rule'
local tab_new = require('resty.core.base').new_tab

local re = require 'ngx.re'
local match = ngx.re.match

local mt = { __index = _M, __tostring = function() return 'Configuration' end }

local function map(func, tbl)
  local newtbl = {}
  for i,v in pairs(tbl) do
    newtbl[i] = func(v)
  end
  return newtbl
end

local function value(val)
    if val ~= null then return val end
end

local Service = require 'apicast.configuration.service'

local noop = function() end
local function readonly_table(table)
    return setmetatable({}, { __newindex = noop, __index = table })
end

local empty_t = readonly_table()
local fake_backend = readonly_table({ endpoint = 'http://127.0.0.1:8081' })

local function backend_endpoint(proxy)
    local backend_endpoint_override = resty_url.parse(env.get("BACKEND_ENDPOINT_OVERRIDE"))
    local backend = backend_endpoint_override or proxy.backend or empty_t

    if backend == empty_t then
        local test_nginx_server_port = env.get('TEST_NGINX_SERVER_PORT')
        if test_nginx_server_port then
            return { endpoint =  'http://127.0.0.1:' .. test_nginx_server_port }
        else
            return fake_backend
        end
    else
        return { endpoint = backend.endpoint or tostring(backend), host = backend.host }
    end
end

local function build_policy_chain(policies)
  if not value(policies) then return nil, 'no policy chain' end

  local chain = tab_new(#policies, 0)

  for i=1, #policies do
      local policy, err = policy_chain.load_policy(policies[i].name, policies[i].version, policies[i].configuration)

      if policy then
        insert(chain, policy)
      elseif err then
        ngx.log(ngx.WARN, 'failed to load policy: ', policies[i].name, ' version: ', policies[i].version, ' err: ', err)
      end
  end

  local built_chain = policy_chain.new(chain)
  built_chain:check_order()
  return built_chain
end

function _M.parse_service(service)
  local backend_version = tostring(service.backend_version)
  local proxy = service.proxy or empty_t
  local backend = backend_endpoint(proxy)

  return Service.new({
      id = tostring(service.id or 'default'),
      system_name = tostring(service.system_name or ''),
      backend_version = backend_version,
      authentication_method = proxy.authentication_method or backend_version,
      hosts = proxy.hosts or { 'localhost' }, -- TODO: verify localhost is good default
      api_backend = proxy.api_backend,
      policy_chain = build_policy_chain(proxy.policy_chain),
      error_auth_failed = proxy.error_auth_failed or 'Authentication failed',
      error_limits_exceeded = proxy.error_limits_exceeded or 'Limits exceeded',
      error_auth_missing = proxy.error_auth_missing or 'Authentication parameters missing',
      auth_failed_headers = proxy.error_headers_auth_failed or 'text/plain; charset=utf-8',
      limits_exceeded_headers = proxy.error_headers_limits_exceeded or 'text/plain; charset=utf-8',
      auth_missing_headers = proxy.error_headers_auth_missing or 'text/plain; charset=utf-8',
      error_no_match = proxy.error_no_match or 'No Mapping Rule matched',
      no_match_headers = proxy.error_headers_no_match or 'text/plain; charset=utf-8',
      no_match_status = proxy.error_status_no_match or 404,
      auth_failed_status = proxy.error_status_auth_failed or 403,
      limits_exceeded_status = proxy.error_status_limits_exceeded or 429,
      auth_missing_status = proxy.error_status_auth_missing or 401,
      oauth_login_url = type(proxy.oauth_login_url) == 'string' and len(proxy.oauth_login_url) > 0 and proxy.oauth_login_url or nil,
      secret_token = proxy.secret_token,
      hostname_rewrite = type(proxy.hostname_rewrite) == 'string' and len(proxy.hostname_rewrite) > 0 and proxy.hostname_rewrite,
      backend_authentication = {
        type = service.backend_authentication_type,
        value = service.backend_authentication_value
      },
      backend = backend,
      oidc = {
        issuer_endpoint = value(proxy.oidc_issuer_endpoint),
        claim_with_client_id = value(proxy.jwt_claim_with_client_id),
        claim_with_client_id_type = proxy.jwt_claim_with_client_id_type or "plain",
      },
      credentials = {
        location = proxy.credentials_location or 'query',
        user_key = lower(proxy.auth_user_key or 'user_key'),
        app_id = lower(proxy.auth_app_id or 'app_id'),
        app_key = lower(proxy.auth_app_key or 'app_key') -- TODO: use App-Key if location is headers
      },
      rules = map(mapping_rule.from_proxy_rule, proxy.proxy_rules or {}),

      -- I'm not happy about this, but we need a way how to serialize back the object for the management API.
      -- And returning the original back is the easiest option for now.
      serializable = service
    })
end

function _M.services_limit()
  local services = {}
  local subset = env.value('APICAST_SERVICES_LIST') or env.value('APICAST_SERVICES')
  if env.value('APICAST_SERVICES') then ngx.log(ngx.WARN, 'DEPRECATION NOTICE: Use APICAST_SERVICES_LIST not APICAST_SERVICES as this will soon be unsupported') end
  if not subset or subset == '' then return services end

  local ids = re.split(subset, ',', 'oj')

  return util.to_hash(ids)
end

function _M.filter_services(services, subset)
  local selected_services = {}
  local service_regexp_filter  = env.value("APICAST_SERVICES_FILTER_BY_URL")

  if service_regexp_filter then
    -- Checking that the regexp sent is correct, if not an empty service list
    -- will be returned.
    local _, err = match("", service_regexp_filter, 'oj')
    if err then
      -- @todo this return and empty list, Apicast will continue running maybe
      -- process need to be stopped here.
      ngx.log(ngx.ERR, "APICAST_SERVICES_FILTER_BY_URL cannot compile and all services are filtering out, error: ", err)
      return selected_services
    end
  end

  subset = subset and util.to_hash(subset) or _M.services_limit()
  if (not subset or not next(subset)) and not service_regexp_filter then return services end
  subset = subset or {}

  for i = 1, #services do
    local service = services[i]
    if service:match_host(service_regexp_filter) or subset[service.id] then
      insert(selected_services, service)
    else
      ngx.log(ngx.WARN, 'filtering out service ', service.id)
    end
  end
  return selected_services
end

function _M.new(configuration)
  configuration = configuration or {}
  local services = (configuration or {}).services or {}

  return setmetatable({
    version = configuration.timestamp,
    services = _M.filter_services(map(_M.parse_service, services)),
    oidc = configuration.oidc or {}
  }, mt)
end

return _M
