local _M = {
  _VERSION = '0.01',
}

local len = string.len
local format = string.format
local pairs = pairs
local ipairs = ipairs
local type = type
local unpack = unpack
local error = error
local tostring = tostring
local tonumber = tonumber
local next = next
local lower = string.lower
local insert = table.insert
local concat = table.concat
local setmetatable = setmetatable
local custom_metric_name = custom_metric_name

local inspect = require 'inspect'
local re = require 'ngx.re'
local env = require 'resty.env'
local resty_url = require 'resty.url'
local custom_metric = env.enabled('APICAST_CUSTOM_METRIC')

local mt = { __index = _M }

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

local function check_custom_metric(custom_metric, req)
  local metric = ngx.req.get_headers()["X-Custom-Metric"]
  ngx.log(ngx.INFO, "metric :" .. inspect(metric))
  if not metric or metric == '' then
    ngx.log(ngx.INFO, "No Custom-Metric Header found")
  end
  return metric
end

local function check_rule(req, rule, usage_t, matched_rules)
  local pattern = rule.regexpified_pattern
  local match = ngx.re.match(req.path, format("^%s", pattern), 'oj')
  local custom_metric_name = req.custom_metric_name
  ngx.log(ngx.INFO, "custom_metric_name :" .. inspect(custom_metric_name))
  
  if custom_metric_name == rule.system_name then
    rule.system_name = custom_metric_name
  end
    
  if match and req.method == rule.method then
    local args = req.args

    if rule.querystring_params(args) then -- may return an empty table
      -- FIXME: this had no effect, what is it supposed to do?
      -- when no querystringparams
      -- in the rule. it's fine
      -- for i,p in ipairs(rule.parameters or {}) do
      --   param[p] = match[i]
      -- end

      insert(matched_rules, rule.pattern)
      usage_t[rule.system_name] = set_or_inc(usage_t, rule.system_name, rule.delta)
    end
  end
end


local function first_values(a)
  local r = {}
  for k,v in pairs(a) do
    if type(v) == "table" then
      r[k] = v[1]
    else
      r[k] = v
    end
  end
  return r
end

local function get_auth_params(method)
  local params

  if method == "GET" then
    params = ngx.req.get_uri_args()
  else
    ngx.req.read_body()
    params = ngx.req.get_post_args()
  end
  return first_values(params)
end

local regex_variable = '\\{[-\\w_]+\\}'

local function check_querystring_params(params, args)
  for param, expected in pairs(params) do
    local m, err = ngx.re.match(expected, regex_variable, 'oj')
    local value = args[param]

    if m then
      if not value then -- regex variable have to have some value
        ngx.log(ngx.DEBUG, 'check query params ' .. param .. ' value missing ' .. tostring(expected))
        return false
      end
    else
      if err then ngx.log(ngx.ERR, 'check match error ' .. err) end

      if value ~= expected then -- normal variables have to have exact value
        ngx.log(ngx.DEBUG, 'check query params does not match ' .. param .. ' value ' .. tostring(value) .. ' == ' .. tostring(expected))
        return false
      end
    end
  end

  return true
end

local Service = require 'configuration.service'

function _M.parse_service(service)
  local backend_version = tostring(service.backend_version)
  local proxy = service.proxy or {}
  local backend = proxy.backend or {}
  local backend_endpoint_override = env.get("BACKEND_ENDPOINT_OVERRIDE")
  local _, _, _, backend_host_override = unpack(resty_url.split(backend_endpoint_override) or {})

  return Service.new({
      id = service.id or 'default',
      backend_version = backend_version,
      hosts = proxy.hosts or { 'localhost' }, -- TODO: verify localhost is good default
      api_backend = proxy.api_backend,
      error_auth_failed = proxy.error_auth_failed,
      error_auth_missing = proxy.error_auth_missing,
      auth_failed_headers = proxy.error_headers_auth_failed,
      auth_missing_headers = proxy.error_headers_auth_missing,
      error_no_match = proxy.error_no_match,
      no_match_headers = proxy.error_headers_no_match,
      no_match_status = proxy.error_status_no_match or 404,
      auth_failed_status = proxy.error_status_auth_failed or 403,
      auth_missing_status = proxy.error_status_auth_missing or 401,
      oauth_login_url = type(proxy.oauth_login_url) == 'string' and len(proxy.oauth_login_url) > 0 and proxy.oauth_login_url or nil,
      secret_token = proxy.secret_token,
      hostname_rewrite = type(proxy.hostname_rewrite) == 'string' and len(proxy.hostname_rewrite) > 0 and proxy.hostname_rewrite,
      backend_authentication = {
        type = service.backend_authentication_type,
        value = service.backend_authentication_value
      },
      backend = {
        endpoint = backend_endpoint_override or backend.endpoint,
        host = backend_host_override or backend.host
      },
      credentials = {
        location = proxy.credentials_location or 'query',
        user_key = lower(proxy.auth_user_key or 'user_key'),
        app_id = lower(proxy.auth_app_id or 'app_id'),
        app_key = lower(proxy.auth_app_key or 'app_key') -- TODO: use App-Key if location is headers
      },
      extract_usage = function (config, request, _)
        local method, url = unpack(re.split(request, " ", 'oj'))
        local path, _ = unpack(re.split(url, "\\?", 'oj'))
        local usage_t =  {}
        local matched_rules = {}
        
        if custom_metric then
          custom_metric_name = check_custom_metric(custom_metric, request)
          ngx.log(ngx.INFO, "custom_metric_name :" .. inspect(custom_metric_name))
        end

        local args = get_auth_params(method)

        ngx.log(ngx.DEBUG, '[mapping] service ' .. config.id .. ' has ' .. #config.rules .. ' rules')
        
        --if custom_metric ~= nil and custom_metric != "" then
          for _,r in ipairs(config.rules) do
            check_rule({path=path, method=method, args=args, custom_metric_name=custom_metric_name}, r, usage_t, matched_rules)
          end
        --else
          --for _,r in ipairs(config.rules) do
            --check_rule({path=path, method=method, args=args}, r, usage_t, matched_rules)
          --end
        --end

        -- if there was no match, usage is set to nil and it will respond a 404, this behavior can be changed
        return usage_t, concat(matched_rules, ", ")
      end,
      rules = map(function(proxy_rule)
        return {
          method = proxy_rule.http_method,
          pattern = proxy_rule.pattern,
          regexpified_pattern = regexpify(proxy_rule.pattern),
          parameters = proxy_rule.parameters,
          querystring_params = function(args)
            return check_querystring_params(proxy_rule.querystring_parameters or {}, args)
          end,
          system_name = proxy_rule.metric_system_name or error('missing metric name of rule ' .. inspect(proxy_rule)),
          delta = proxy_rule.delta
        }
      end, proxy.proxy_rules or {}),

      -- I'm not happy about this, but we need a way how to serialize back the object for the management API.
      -- And returning the original back is the easiest option for now.
      serializable = service
    })
end

local function to_hash(table)
  local t = {}

  for _,id in ipairs(table) do
    local n = tonumber(id)

    if n then
      t[n] = true
    end
  end

  return t
end

function _M.services_limit()
  local services = {}
  local subset = env.get('APICAST_SERVICES')
  if not subset or subset == '' then return services end

  local ids = re.split(subset, ',', 'oj')

  return to_hash(ids)
end

function _M.filter_services(services, subset)
  subset = subset and to_hash(subset) or _M.services_limit()
  if not subset or not next(subset) then return services end

  local s = {}

  for _, service in ipairs(services) do
    if subset[service.id] then
      s[#s+1] = service
    end
  end

  return s
end

function _M.new(configuration)
  configuration = configuration or {}
  local services = (configuration or {}).services or {}

  return setmetatable({
    version = configuration.timestamp,
    services = _M.filter_services(map(_M.parse_service, services))
  }, mt)
end

return _M
