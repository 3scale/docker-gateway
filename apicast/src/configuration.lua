local _M = {
  _VERSION = '0.01',
}

local len = string.len
local format = string.format
local find = string.find
local pairs = pairs
local type = type
local error = error
local tostring = tostring
local next = next
local lower = string.lower
local insert = table.insert
local concat = table.concat
local setmetatable = setmetatable
local re_match = ngx.re.match

local inspect = require 'inspect'
local re = require 'ngx.re'
local env = require 'resty.env'
local resty_url = require 'resty.url'
local util = require 'util'

local url_rewriting = env.enabled('APICAST_URL_REWRITING')

local mt = { __index = _M, __tostring = function() return 'Configuration' end }

local function map(func, tbl)
  local newtbl = {}
  for i,v in pairs(tbl) do
    newtbl[i] = func(v)
  end
  return newtbl
end

local function set_or_inc(t, name, delta)
  return (t[name] or 0) + (delta or 0)
end

local function regexpify(path)
  return path:gsub('?.*', ''):gsub("{.-}", '([\\w_.-]+)'):gsub("%.", "\\.")
end

function _M.get_rewrite_url(rule, params)

  local rewrite_url = rule.redirect_url
  if not rewrite_url or rewrite_url == "" then return nil end

  -- fill the wildcard with captures
  for param, value in pairs(params) do
    local wildcard = '{'..param..'}'
    rewrite_url = rewrite_url:gsub(wildcard, value)
  end

  -- merge the query parameters from the request and the rewrite_url of the rule
  local rule_query = re.split(rewrite_url,'\\?','oj')[2]
  local args = ngx.req.get_uri_args()
  local req_query = ngx.var.args or ''

  -- remove the query arg from the original request, if it is present in the rewrite URL
  for key in pairs(args) do
    local param = format("%s=",key)
    local m = find(rewrite_url, param)
    if m then
      param = (param..'[^&]+&?')
      req_query = req_query:gsub(param,'')
    end
  end

  if req_query ~= '' then
    local merge_char = (rule_query == nil or rule_query == '') and '?' or '&'
    rewrite_url = rewrite_url .. merge_char .. req_query
  end

  return rewrite_url
end

local function hash_to_array(hash)
  local array = {}
  for k,v in pairs(hash or {}) do
    insert(array, { k, v })
  end
  return array
end

local regex_variable = '\\{[-\\w_]+\\}'

local function check_querystring_params(querystring_parameters, args)
  local params = hash_to_array(querystring_parameters)

  local match = true
  local matched_query_params = {}

  for i=1, #params do
    local param = params[i][1]
    local expected = params[i][2]

    local m, err = re_match(expected, regex_variable, 'oj')
    local value = args[param]

    -- query parameter value is a defined as wildcard
    if m then
      if not value then -- regex variable have to have some value
        ngx.log(ngx.DEBUG, 'check query params ', param, ' value missing ', expected)
        match = false
        break
      end
      -- TODO: see if there is a better way to do it, maybe with 'match'
      local wildcard_name = m[0]:gsub('{',''):gsub('}','')
      matched_query_params[wildcard_name] = value
    else
      -- query parameter value is exact
      if err then ngx.log(ngx.ERR, 'check match error ', err) end

      -- if many values were passed use the last one
      if type(value) == 'table' then
        value = value[#value]
      end

      if value ~= expected then -- normal variables have to have exact value
        ngx.log(ngx.DEBUG, 'check query params does not match ', param, ' value ' , value, ' == ', expected)
        match = false
        break
      end
    end
  end

  return match, matched_query_params
end

local function check_rule(req, rule, usage_t, matched_rules, params)
  local rewrite_url = nil

  local pattern = rule.regexpified_pattern
  local match = re_match(req.path, format("^%s", pattern), 'oj')

  if match and req.method == rule.method then
    local args = req.args

    local querystring_check_ok, matched_query_params = check_querystring_params(rule.querystring_parameters, args)

    if querystring_check_ok then
      local system_name = rule.system_name

      if url_rewriting then

        local parameters = {} -- parameters from wildcards

        -- Extracting path parameters matching wildcards
        for i,p in ipairs(rule.parameters or {}) do
          parameters[p] = match[i]
        end

        -- add wildcards from query parameters
        for k,v in pairs(matched_query_params) do
          parameters[k] = v
        end

        rewrite_url = _M.get_rewrite_url(rule, parameters)
      end

      local value = set_or_inc(usage_t, system_name, rule.delta)

      usage_t[system_name] = value
      params['usage[' .. system_name .. ']'] = value
      insert(matched_rules, rule.pattern)
    end
  end

  return rewrite_url
end

local function get_params(method)
  local params = ngx.req.get_uri_args()

  if method == "GET" then
    return params
  else
    ngx.req.read_body()
    local body_params = ngx.req.get_post_args()

    -- Adds to body_params URI params that are not included in the body. Doing
    -- the reverse would be more expensive, because in general, we expect the
    -- size of body_params to be larger than the size of params.
    setmetatable(body_params, { __index = params })

    return body_params
  end
end

local Service = require 'configuration.service'

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

function _M.parse_service(service)
  local backend_version = tostring(service.backend_version)
  local proxy = service.proxy or empty_t
  local backend = backend_endpoint(proxy)


  return Service.new({
      id = tostring(service.id or 'default'),
      backend_version = backend_version,
      authentication_method = proxy.authentication_method or backend_version,
      hosts = proxy.hosts or { 'localhost' }, -- TODO: verify localhost is good default
      api_backend = proxy.api_backend,
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
        issuer_endpoint = proxy.oidc_issuer_endpoint ~= ngx.null and proxy.oidc_issuer_endpoint
      },
      credentials = {
        location = proxy.credentials_location or 'query',
        user_key = lower(proxy.auth_user_key or 'user_key'),
        app_id = lower(proxy.auth_app_id or 'app_id'),
        app_key = lower(proxy.auth_app_key or 'app_key') -- TODO: use App-Key if location is headers
      },
      extract_usage = function (config, request, _)
        local req = re.split(request, " ", 'oj')
        local method, url = req[1], req[2]
        local path = re.split(url, "\\?", 'oj')[1]
        local usage_t =  {}
        local matched_rules = {}
        local params = {}
        local rules = config.rules

        local args = get_params(method)

        ngx.log(ngx.DEBUG, '[mapping] service ', config.id, ' has ', #config.rules, ' rules')

        -- Only for URL rewriting feature:
        -- Stores the rewrite_urls taking into account the wildcards values
        local rewrite_urls = {}

        for i = 1, #rules do
          local rewrite_url = check_rule({path=path, method=method, args=args}, rules[i], usage_t, matched_rules, params)
          if rewrite_url then
            insert(rewrite_urls, rewrite_url)
          end
        end

        -- if there was no match, usage is set to nil and it will respond a 404, this behavior can be changed
        return usage_t, concat(matched_rules, ", "), params, rewrite_urls
      end,
      rules = map(function(proxy_rule)
        return {
          method = proxy_rule.http_method,
          pattern = proxy_rule.pattern,
          regexpified_pattern = regexpify(proxy_rule.pattern),
          parameters = proxy_rule.parameters,
          querystring_parameters = proxy_rule.querystring_parameters,
          system_name = proxy_rule.metric_system_name or error('missing metric name of rule ' .. inspect(proxy_rule)),
          delta = proxy_rule.delta,
          redirect_url = proxy_rule.redirect_url
        }
      end, proxy.proxy_rules or {}),

      -- I'm not happy about this, but we need a way how to serialize back the object for the management API.
      -- And returning the original back is the easiest option for now.
      serializable = service
    })
end

function _M.services_limit()
  local services = {}
  local subset = env.get('APICAST_SERVICES')
  if not subset or subset == '' then return services end

  local ids = re.split(subset, ',', 'oj')

  return util.to_hash(ids)
end

function _M.filter_services(services, subset)
  subset = subset and util.to_hash(subset) or _M.services_limit()
  if not subset or not next(subset) then return services end

  local s = {}

  for i = 1, #services do
    local service = services[i]
    if subset[service.id] then
      insert(s, service)
    else
      ngx.log(ngx.WARN, 'filtering out service ', service.id)
    end
  end

  return s
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
