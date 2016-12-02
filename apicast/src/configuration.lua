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
local open = io.open
local getenv = os.getenv
local assert = assert
local lower = string.lower
local insert = table.insert
local concat = table.concat
local pcall = pcall
local setmetatable = setmetatable

local util = require 'util'
local split = util.string_split

local inspect = require 'inspect'
local cjson = require 'cjson'

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

local function check_rule(req, rule, usage_t, matched_rules)
  local param = {}
  local pattern = rule.regexpified_pattern
  local match = ngx.re.match(req.path, format("^%s", pattern), 'oj')

  if match and req.method == rule.method then
    local args = req.args

    if rule.querystring_params(args) then -- may return an empty table
      -- when no querystringparams
      -- in the rule. it's fine

      -- XXX: this params table is not used anywhere else
      for i,p in ipairs(rule.parameters or {}) do
        param[p] = match[i]
      end

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

function _M.parse_service(service)
  local backend_version = tostring(service.backend_version)
  local proxy = service.proxy or {}
  local backend = proxy.backend or {}

  return {
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
        endpoint = backend.endpoint,
        host = backend.host
      },
      credentials = {
        location = proxy.credentials_location or 'query',
        user_key = lower(proxy.auth_user_key or 'user_key'),
        app_id = lower(proxy.auth_app_id or 'app_id'),
        app_key = lower(proxy.auth_app_key or 'app_key') -- TODO: use App-Key if location is headers
      },
      get_credentials = function(_, params)
        local credentials
        if backend_version == '1' then
          credentials = params.user_key
        elseif backend_version == '2' then
          credentials = (params.app_id and params.app_key)
        elseif backend_version == 'oauth' then
          credentials = (params.access_token or params.authorization)
        else
          error("Unknown backend version: " .. tostring(backend_version))
        end
        return credentials
      end,
      extract_usage = function (config, request, _)
        local method, url = unpack(split(request," "))
        local path, _ = unpack(split(url, "?"))
        local usage_t =  {}
        local matched_rules = {}

        -- XXX: get_auth_params gets the params from the body for the not-GET calls, which probably 
        -- doesn't make sense for the pattern matching, as we only can use queryparams in the 
        -- mapping rules
        local args = get_auth_params(method)

        ngx.log(ngx.DEBUG, '[mapping] service ' .. config.id .. ' has ' .. #config.rules .. ' rules')

        for _,r in ipairs(config.rules) do
          check_rule({path=path, method=method, args=args}, r, usage_t, matched_rules)
        end

        -- if there was no match, usage is set to nil and it will respond a 404, this behavior can be changed
        return usage_t, concat(matched_rules, ", ")
      end,
      -- Given a request, extracts from its params the credentials of the
      -- service according to its backend version.
      -- This method returns a table that contains:
      --     user_key when backend version == 1
      --     app_id and app_key when backend version == 2
      --     access_token when backen version == oauth
      --     empty when backend version is unknown

      -- XXX: This actually will not return the correct credentials, because it doesn't take into
      -- account the credentials location and the names of the user_key and app_id (configured in
      -- the service)
      -- also, this replicates the behavior made in provider.access(), so I suggest to implement this
      -- function properly (see comments in provider.access()), and reuse it in provider.access()
      extract_credentials = function(_, request)
        local auth_params = get_auth_params(split(request, " ")[1])

        local result = {}
        if backend_version == '1' then
          result.user_key = auth_params.user_key
        elseif backend_version == '2' then
          result.app_id = auth_params.app_id
          result.app_key = auth_params.app_key
        elseif backend_version == 'oauth' then
          result.access_token = auth_params.access_token
        end

        return result
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
      end, proxy.proxy_rules or {})
    }
end

function _M.decode(contents, encoder)
  if not contents then return nil end
  if type(contents) == 'string' and len(contents) == 0 then return nil end
  if type(contents) == 'table' then return contents end
  if contents == '\n' then return nil end

  encoder = encoder or cjson

  local ok, ret = pcall(encoder.decode, contents)

  if not ok then
    return nil, ret
  end

  if ret == encoder.null then
    return nil
  end

  return ret
end

function _M.encode(contents, encoder)
  if type(contents) == 'string' then return contents end
  
  encoder = encoder or cjson

  return encoder.encode(contents)
end

function _M.parse(contents, encoder)
  local config, err = _M.decode(contents, encoder)

  if config then
    return _M.new(config)
  else
    return nil, err
  end
end

function _M.read(path)
  if not path or len(tostring(path)) == 0 then
    return nil, 'missing path'
  end
  ngx.log(ngx.INFO, 'configuration loading file ' .. path)
  return assert(open(path)):read('*a')
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
  local subset = os.getenv('APICAST_SERVICES')
  if not subset or subset == '' then return services end

  local ids = split(subset, ',')

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
    services = _M.filter_services(map(_M.parse_service, services)),
    debug_header = configuration.provider_key -- TODO: change this to something secure
  }, mt)
end

function _M.boot()
  local endpoint = getenv('THREESCALE_PORTAL_ENDPOINT')
  local file = getenv('THREESCALE_CONFIG_FILE')

  return _M.load() or _M.read(file) or _M.wait(endpoint, 3) or _M.download(endpoint) or _M.curl(endpoint) or error('missing configuration')
end

function _M.save(config)
  _M.config = config -- TODO: use shmem
end

function _M.load()
  return _M.config
end


-- Cosocket API is not available in the init_by_lua* context (see more here: https://github.com/openresty/lua-nginx-module#cosockets-not-available-everywhere)
-- For this reason a new process needs to be started to download the configuration through 3scale API
function _M.init()
  local config, exit, code = util.system("cd '" .. ngx.config.prefix() .."' && libexec/boot")

  if config then
    if len(config) > 0 then return config end
  elseif exit then
    if code then
      ngx.log(ngx.ERR, 'boot could not get configuration, ' .. tostring(exit) .. ': '.. tostring(code))
      return nil, exit
    else
      ngx.log(ngx.ERR, 'boot failed read: '.. tostring(exit))
      return nil, exit
    end
  end
end

-- wait until a connection to a TCP socket can be established
function _M.wait(endpoint, timeout)
  local now = ngx.now()
  local fin = now + timeout
  local url, err = _M.url(endpoint)

  ngx.log(ngx.DEBUG, 'going to wait for ' .. tostring(timeout))

  if not url and err then
    return nil, err
  end

  local scheme, _, _, host, port, _ = unpack(url)

  if not port and scheme then
    if scheme == 'http' then
      port = 80
    elseif scheme == 'https' then
      port = 443
    else
      return nil, "unknown scheme " .. tostring(scheme) .. ' and port missing'
    end
  end

  while now < fin do
    local sock = ngx.socket.tcp()
    local ok

    ok, err = sock:connect(host, port)

    if ok then
      ngx.log(ngx.DEBUG, 'connected to ' .. host .. ':' .. tostring(port))
      sock:close()
      return
    else
      ngx.log(ngx.DEBUG, 'failed to connect to ' .. host .. ':' .. tostring(port) .. ': ' .. err)
    end

    ngx.sleep(0.1)
    ngx.update_time()
    now = ngx.now()
  end

  return nil, err
end

function _M.download(endpoint)
  local url, err = _M.url(endpoint)

  if not url and err then
    return nil, err
  end

  local scheme, user, pass, host, port, path = unpack(url)
  if port then host = concat({host, port}, ':') end

  url = concat({ scheme, '://', host, path or '/admin/api/nginx/spec.json' }, '')

  local http = require "resty.http"
  local httpc = http.new()
  local headers = {}

  httpc:set_timeout(10000)

  if user or pass then
    headers['Authorization'] = "Basic " .. ngx.encode_base64(concat({ user or '', pass or '' }, ':'))
  end

  -- TODO: this does not fully implement HTTP spec, it first should send
  -- request without Authentication and then send it after gettting 401

  ngx.log(ngx.INFO, 'configuration request sent: ' .. url)

  local res
  res, err = httpc:request_uri(url, {
    method = "GET",
    headers = headers,
    ssl_verify = false
  })

  if err then
    ngx.log(ngx.WARN, 'configuration download error: ' .. err)
  end

  local body = res and (res.body or res:read_body())

  if body and res.status == 200 then
    ngx.log(ngx.DEBUG, 'configuration response received:' .. body)

    local ok
    ok, err = _M.decode(body)
    if ok then
      return body
    else
      ngx.log(ngx.WARN, 'configuration could not be decoded: ', body)
      return nil, err
    end
  else
    return nil, err or res.reason
  end
end

function _M.url(endpoint)
  if not endpoint then
    return nil, 'missing endpoint'
  end

  local match = ngx.re.match(endpoint, "^(https?):\\/\\/(?:(.+)@)?([^\\/\\s]+?)(?::(\\d+))?(\\/.+)?$", 'oj')

  if not match then
    return nil, 'invalid endpoint' -- TODO: maybe improve the error message?
  end

  local scheme, userinfo, host, port, path = unpack(match)

  if path == '/' then path = nil end

  match = userinfo and ngx.re.match(tostring(userinfo), "^([^:\\s]+)?(?::(.*))?$", 'oj')
  local user, pass = unpack(match or {})

  return { scheme, user or false, pass or false, host, port or false, path or nil }
end


-- curl is used because resty command that runs libexec/boot does not have correct DNS resolvers set up
-- resty is using google's public DNS servers and there is no way to change that
function _M.curl(endpoint)
  local url, err = _M.url(endpoint)

  if not url and err then
    return nil, err
  end

  local scheme, user, pass, host, port, path = unpack(url)

  if port then host = concat({host, port}, ':') end

  url = concat({ scheme, '://', concat({user or '', pass or ''}, ':'), '@', host, path or '/admin/api/nginx/spec.json' }, '')

  local config, exit, code = util.system('curl --silent --show-error --fail --max-time 3 --location ' .. url)

  ngx.log(ngx.INFO, 'configuration request sent: ' .. url)

  if config then
    ngx.log(ngx.DEBUG, 'configuration response received:' .. config)
    return config
  else
    if code then
      ngx.log(ngx.ERR, 'configuration download error ' .. exit .. ' ' .. code)
      return nil, 'curl fished with ' .. exit .. ' ' .. code
    else
      ngx.log(ngx.WARN, 'configuration download error: ' .. exit)
      return nil, exit
    end
  end
end

return _M
