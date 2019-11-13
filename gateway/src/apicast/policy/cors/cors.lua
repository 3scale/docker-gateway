--- CORS policy
-- This policy enables CORS (Cross Origin Resource Sharing) request handling.
-- The policy is configurable. Users can specify the values for the following
-- headers in the response:
--
--   - Access-Control-Allow-Headers
--   - Access-Control-Allow-Methods
--   - Access-Control-Allow-Origin
--   - Access-Control-Allow-Credentials
--
-- By default, those headers are set so all the requests are allowed. For
-- example, if the request contains the 'Origin' header set to 'example.com',
-- by default, 'Access-Control-Allow-Origin' in the response will be set to
-- 'example.com' too.

local policy = require('apicast.policy')
local _M = policy.new('CORS Policy', 'builtin')

local new = _M.new

--- Initialize a CORS policy
-- @tparam[opt] table config
-- @field[opt] allow_headers Table with the allowed headers (e.g. Content-Type)
-- @field[opt] allow_methods Table with the allowed methods (GET, POST, etc.)
-- @field[opt] allow_origin Allowed origins (e.g. 'http://example.com', '*')
-- @field[opt] allow_credentials Boolean
function _M.new(config)
  local self = new(config)
  self.config = config or {}
  return self
end

local function set_access_control_allow_headers(allow_headers)
  local value = allow_headers or ngx.var.http_access_control_request_headers
  ngx.header['Access-Control-Allow-Headers'] = value
end

local function set_access_control_allow_methods(allow_methods)
  local value = allow_methods or ngx.var.http_access_control_request_method
  ngx.header['Access-Control-Allow-Methods'] = value
end

local function set_access_control_allow_origin(allow_origin, default)
  ngx.header['Access-Control-Allow-Origin'] = allow_origin or default
end

local function set_access_control_allow_credentials(allow_credentials)
  local value = allow_credentials
  if value == nil then value = true end
  ngx.header['Access-Control-Allow-Credentials'] = value
end

local function set_cors_headers(config)
  local origin = ngx.var.http_origin
  if not origin then return end

  set_access_control_allow_headers(config.allow_headers)
  set_access_control_allow_methods(config.allow_methods)
  set_access_control_allow_origin(config.allow_origin, origin)
  set_access_control_allow_credentials(config.allow_credentials)
end

local function cors_preflight_response()
  -- with ngx.exit(204), header_filter is run. CORS headers will be set there.
  ngx.status = 204
  ngx.exit(ngx.status)
end

local function is_cors_preflight()
  return ngx.req.get_method() == 'OPTIONS' and
         ngx.var.http_origin and
         ngx.var.http_access_control_request_method
end

function _M.rewrite(_)
  if is_cors_preflight() then
    return cors_preflight_response()
  end
end

function _M:header_filter()
  set_cors_headers(self.config)
end

return _M
