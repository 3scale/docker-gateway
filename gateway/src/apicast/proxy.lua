------------
-- Proxy
-- Module that handles the request authentication and proxying upstream.
--
-- @module proxy
-- @author mikz
-- @license Apache License Version 2.0

local env = require 'resty.env'
local custom_config = env.get('APICAST_CUSTOM_CONFIG')
local resty_lrucache = require('resty.lrucache')
local backend_cache_handler = require('apicast.backend.cache_handler')
local Usage = require('apicast.usage')
local errors = require('apicast.errors')
local Upstream = require('apicast.upstream')
local escape = require("resty.http.uri_escape")

local assert = assert
local type = type
local insert = table.insert
local concat = table.concat
local gsub = string.gsub
local tonumber = tonumber
local setmetatable = setmetatable
local ipairs = ipairs
local encode_args = ngx.encode_args
local backend_client = require('apicast.backend_client')

local response_codes = env.enabled('APICAST_RESPONSE_CODES')
local reporting_executor = require('resty.concurrent.immediate_executor')
do
  local reporting_threads = tonumber(env.value('APICAST_REPORTING_THREADS')) or 0

  if reporting_threads > 0 then
    reporting_executor = require('resty.concurrent.timer_pool_executor').new({
      max_timers = reporting_threads,
      fallback_policy = 'caller_runs',
    })

    ngx.log(ngx.WARN, 'using experimental asynchronous reporting threads: ', reporting_threads)
  end
end

local _M = { }

local mt = {
  __index = _M
}

function _M.shared_cache()
  return ngx.shared.api_keys or resty_lrucache.new(1)
end

function _M.new(configuration)
  local cache = _M.shared_cache() or error('missing cache store')

  if not cache then
    ngx.log(ngx.WARN, 'apicast cache error missing shared memory zone api_keys')
  end

  local cache_handler = backend_cache_handler.new(env.get('APICAST_BACKEND_CACHE_HANDLER'))

  return setmetatable({
    configuration = assert(configuration, 'missing proxy configuration'),
    cache = cache,
    cache_handler = cache_handler,
    http_ng_backend = nil,

    -- Params to send in 3scale backend calls that are not the typical ones
    -- (credentials, usage, etc.).
    -- This allows us, for example, to send a referrer.
    extra_params_backend_authrep = {}
  }, mt)
end

local function debug_header_enabled(service)
  local debug_header_value = ngx.var.http_x_3scale_debug
  return debug_header_value and debug_header_value == service.backend_authentication.value
end

local function output_debug_headers(service, usage, credentials)
  ngx.log(ngx.INFO, 'usage: ', usage, ' credentials: ', credentials)

  if debug_header_enabled(service) then
    ngx.header["X-3scale-matched-rules"] = ngx.ctx.matched_patterns
    ngx.header["X-3scale-credentials"]   = credentials
    ngx.header["X-3scale-usage"]         = usage
    ngx.header["X-3scale-hostname"]      = ngx.var.hostname
    ngx.header["X-3scale-service-id"]    = service.id
    ngx.header["X-3scale-service-name"]  = service.serializable.system_name
  end
end

local function matched_patterns(matched_rules)
  local patterns = {}

  for _, rule in ipairs(matched_rules) do
    insert(patterns, rule.pattern)
  end

  return patterns
end

local function build_backend_client(self, service)
  return assert(backend_client:new(service, self.http_ng_backend), 'missing backend')
end

function _M:authorize(service, usage, credentials, ttl)
  if not usage or not credentials then return nil, 'missing usage or credentials' end

  local formatted_usage = usage:format()

  local encoded_usage = encode_args(formatted_usage)
  if encoded_usage == '' then
    return errors.no_match(service)
  end
  local encoded_credentials = encode_args(credentials)

  output_debug_headers(service, encoded_usage, encoded_credentials)

  -- NYI: return to lower frame
  local cached_key = ngx.var.cached_key .. ":" .. encoded_usage

  local encoded_extra_params = encode_args(self.extra_params_backend_authrep)
  if encoded_extra_params ~= '' then
    cached_key = cached_key .. ":" .. encoded_extra_params
  end

  local cache = self.cache
  local is_known = cache:get(cached_key)

  if is_known == 200 then
    ngx.log(ngx.DEBUG, 'apicast cache hit key: ', cached_key)
    ngx.var.cached_key = cached_key
  else
    ngx.log(ngx.INFO, 'apicast cache miss key: ', cached_key, ' value: ', is_known)

    -- set cached_key to nil to avoid doing the authrep in post_action
    ngx.var.cached_key = nil

    local backend = build_backend_client(self, service)
    local res = backend:authrep(formatted_usage, credentials, self.extra_params_backend_authrep)

    local authorized, rejection_reason, retry_after = self:handle_backend_response(
      cached_key, res, ttl
    )

    if not authorized then
      if rejection_reason == 'limits_exceeded' then
        return errors.limits_exceeded(service, retry_after)
      else -- Generic error for now. Maybe return different ones in the future.
        return errors.authorization_failed(service)
      end
    end
  end
end

function _M.set_service(service)
  if not service then
    return errors.service_not_found()
  end

  ngx.ctx.service = service
  ngx.var.service_id = service.id

  return service
end

function _M.get_upstream(service, context)
  service = service or ngx.ctx.service

  if not service then
    return errors.service_not_found()
  end
  local upstream, err = Upstream.new(service.api_backend)
  if not upstream then
    return nil, err
  end

  if context and context.upstream_location_name then
    upstream.location_name = context.upstream_location_name
  end

  upstream:use_host_header(service.hostname_rewrite)

  return upstream
end

local function handle_oauth(service)
  local oauth, err = service:oauth()

  if oauth then
    ngx.log(ngx.DEBUG, 'using OAuth: ', oauth)

    if err then
      ngx.log(ngx.WARN, 'failed to initialize ', oauth, ' for service ', service.id, ': ', err)
    end
  end

  if oauth and oauth.call then
    local f, params = oauth:call(service)

    if f then
      ngx.log(ngx.DEBUG, 'OAuth matched route')
      return f(params) -- not really about the return value but showing something will call ngx.exit
    end
  end

  return oauth
end

function _M:rewrite(service, context)
  service = _M.set_service(service or ngx.ctx.service)

  -- handle_oauth can terminate the request
  self.oauth = handle_oauth(service)

  ngx.var.secret_token = service.secret_token

  -- Another policy might have already extracted the creds.
  local credentials =  context.extracted_credentials

  local err
  if not credentials then
    credentials, err = service:extract_credentials()
  end

  if not credentials then
    ngx.log(ngx.WARN, "cannot get credentials: ", err or 'unknown error')
    return errors.no_credentials(service)
  end

  -- URI need to be escaped to be able to match values with special characters
  -- (like spaces), request_uri is the original one, but rewrite_uri can modify
  -- the value and mapping rule will not match.
  -- Example:  if URI is `/foo /bar` it will be translated to `/foo%20/bar`
  local target_uri = escape.escape_uri(ngx.var.uri)
  local usage, matched_rules = service:get_usage(ngx.req.get_method(), target_uri)
  local cached_key = { service.id }

  -- remove integer keys for serialization
  -- as ngx.encode_args can't serialize integer keys
  -- and verify all the keys exist
  for i=1,#credentials do
    local val = credentials[i]
    if not val then
      return errors.no_credentials(service)
    else
      credentials[i] = nil
    end

    insert(cached_key, val)
  end

  local ctx = ngx.ctx
  local var = ngx.var

  -- save those tables in context so they can be used in the backend client
  context.usage = context.usage or Usage.new()
  context.usage:merge(usage)

  ctx.usage = context.usage
  ctx.matched_rules = matched_rules
  ctx.credentials = credentials

  var.cached_key = concat(cached_key, ':')

  if debug_header_enabled(service) then
    local patterns = matched_patterns(matched_rules)
    ctx.matched_patterns = concat(patterns, ', ')
  end

  local ttl

  if self.oauth then
    local jwt_payload
    credentials, ttl, jwt_payload, err = self.oauth:transform_credentials(credentials, service.id)

    if err then
      ngx.log(ngx.DEBUG, 'oauth failed with ', err)
      return errors.authorization_failed(service)
    end
    ctx.credentials = credentials
    ctx.ttl = ttl
    context.jwt = jwt_payload
  end

  context.credentials = ctx.credentials
end

function _M:access(service, usage, credentials, ttl)
  local ctx = ngx.ctx
  local final_usage = usage or ctx.usage

  -- If routing policy changes the upstream and it only belongs to a specified
  -- owner, we need to filter out the usage for APIs that are not used at all.
  if ctx.context.route_upstream_usage_cleanup then
    ctx.context:route_upstream_usage_cleanup(final_usage, ctx.matched_rules)
  end
  return self:authorize(service, final_usage, credentials or ctx.credentials, ttl or ctx.ttl)

end

local function response_codes_data(status)
  if not response_codes then
    return {}
  else
    return { ["log[code]"] = status }
  end
end

local function post_action(self, cached_key, service, credentials, formatted_usage, response_status_code)
  local backend = build_backend_client(self, service)
  local res = backend:authrep(
          formatted_usage,
          credentials,
          response_codes_data(response_status_code),
          self.extra_params_backend_authrep
  )

  self:handle_backend_response(cached_key, res)
end

function _M:post_action(context)
  local cached_key = ngx.var.cached_key

  if not cached_key or cached_key == "null" or cached_key == '' then
      ngx.log(ngx.INFO, '[async] skipping after action, no cached key')
      return
  end

  ngx.log(ngx.INFO, '[async] reporting to backend asynchronously, cached_key: ', cached_key)

  local service_id = ngx.var.service_id
  local service = ngx.ctx.service or self.configuration:find_by_id(service_id)

  local credentials = context.credentials
  local formatted_usage = context.usage:format()

  reporting_executor:post(post_action, self, cached_key, service, credentials, formatted_usage, ngx.var.status)
end

-- Returns the rejection reason from the headers of a 3scale backend response.
-- The header is set only when the authrep call to backend enables the option
-- to get the rejection reason. This is specified in the '3scale-options'
-- header of the request.
local function rejection_reason(response_headers)
  return response_headers and response_headers['3scale-rejection-reason']
end

-- Returns the '3scale-limit-reset' from the headers of a 3scale backend
-- response.
-- This header is set only when enabled via the '3scale-options' header of the
-- request.
local function limit_reset(response_headers)
  return response_headers and response_headers['3scale-limit-reset']
end

-- Returns the '3scale-limit-max-value' from the headers of a 3scale backend
-- response.
-- This header is set only when enabled via the '3scale-options' header of the
-- request.
local function limit_max_value(response_headers)
  local max = response_headers and response_headers['3scale-limit-max-value']
  return tonumber(max)
end

local function backend_is_unavailable(response_status)
  -- 499 is a non-standard error returned by NGINX (client closed request)
  return not response_status or response_status == 0 or response_status >= 499
end

function _M:handle_backend_response(cached_key, response, ttl)
  ngx.log(ngx.DEBUG, '[backend] response status: ', response.status, ' body: ', response.body)

  self.cache_handler(self.cache, cached_key, response, ttl)

  if backend_is_unavailable(response.status) then
    return self.cache:get(cached_key) == 200
  end

  local authorized = (response.status == 200)
  local unauthorized_reason = not authorized and rejection_reason(response.headers)
  local retry_after = not authorized and limit_reset(response.headers)
  local limit_max = limit_max_value(response.headers)

  -- This is for disabled metrics. Those have a limit of 0 in the 3scale
  -- backend. When authorizing a disabled metric, backend returns "limits
  -- exceeded" as the unauthorized reason. However, from the point of view of
  -- APIcast, we want to distinguish between limits exceeded vs disabled
  -- metric. That's why we reset the reason. The generic auth fail (403) will
  -- be returned.
  if limit_max == 0 and unauthorized_reason == 'limits_exceeded' then
    unauthorized_reason = nil
  end

  return authorized, unauthorized_reason, retry_after
end

if custom_config then
  local path = package.path
  local module = gsub(custom_config, '%.lua$', '') -- strip .lua from end of the file
  package.path = package.path .. ';' .. './?.lua;'
  local ok, c = pcall(function() return require(module) end)

  if not ok then
    local chunk, _ = loadfile(custom_config)

    if chunk then
      ok = true
      c =  chunk()
    end
  end

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
