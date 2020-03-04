------------
-- Backend Client
-- HTTP client using @{http_ng.HTTP} to call 3scale backend.
--
-- @module backend_client
-- @author mikz
-- @license Apache License Version 2.0

--- Backend Client
-- @type backend_client

local setmetatable = setmetatable
local concat = table.concat
local insert = table.insert
local len = string.len
local format = string.format
local pairs = pairs

local http_ng = require('resty.http_ng')
local user_agent = require('apicast.user_agent')
local resty_url = require('resty.url')
local resty_env = require('resty.env')
local backend_calls_metrics = require('apicast.metrics.3scale_backend_calls')

local http_proxy = require('resty.http.proxy')
local http_ng_resty = require('resty.http_ng.backend.resty')

local _M = {
  endpoint = resty_env.value("BACKEND_ENDPOINT_OVERRIDE")
}

local mt = { __index = _M }

local function detect_http_client(endpoint)
  local uri = resty_url.parse(endpoint)
  local proxy = http_proxy.find(uri)

  if proxy then -- use default client
    return
  else
    return http_ng_resty
  end
end

--- Return new instance of backend client
-- @tparam Service service object with service definition
-- @tparam http_ng.backend http_client async/test/custom http backend
-- @treturn backend_client
function _M:new(service, http_client)
  local endpoint = self.endpoint or (service and service.backend and service.backend.endpoint) or error('missing endpoint')
  local service_id = service.id

  if not endpoint then
    ngx.log(ngx.WARN, 'service ', service_id, ' does not have backend endpoint configured')
  end

  local authentication = { service_id = service_id }

  if service.backend_authentication and service.backend_authentication.type then
    authentication[service.backend_authentication.type] = service.backend_authentication.value
  end

  local backend, err = resty_url.split(endpoint)

  if not backend and err then
    return nil, err
  end

  if not http_client then
    http_client = detect_http_client(endpoint)
  end

  local client = http_ng.new{
    backend = http_client,
    options = {
      headers = {
        user_agent = user_agent(),
        host = service.backend and service.backend.host or backend[4],
      },
      ssl = { verify = resty_env.enabled('OPENSSL_VERIFY') }
    }
  }

  return setmetatable({
    version = service.backend_version,
    endpoint = endpoint,
    service_id = service_id,
    authentication = authentication,
    http_client = client,
    uses_oauth_native = (service.backend_version == 'oauth' and
                         service.authentication_method ~= 'oidc')
  }, mt)
end

local function inc_metrics(endpoint, status)
  backend_calls_metrics.report(endpoint, status)
end

local function build_args(args)
  local query = {}

  for i=1, #args do
    local arg = ngx.encode_args(args[i])
    if len(arg) > 0 then
      insert(query, arg)
    end
  end

  return concat(query, '&')
end

local function build_url(self, path, ...)
  local endpoint = self.endpoint

  if not endpoint then
    return nil, 'missing endpoint'
  end

  local args = { self.authentication, ... }
  return resty_url.join(endpoint, '', path .. '?' .. build_args(args))
end

local function call_backend_transaction(self, path, options, ...)
  local http_client = self.http_client

  if not http_client then
    return nil, 'not initialized'
  end

  local url = build_url(self, path, ...)
  local res = http_client.get(url, options)

  ngx.log(ngx.INFO, 'backend client uri: ', url, ' ok: ', res.ok, ' status: ', res.status, ' body: ', res.body, ' error: ', res.error)

  return res
end

local function authrep_path(using_oauth)
  return (using_oauth and '/transactions/oauth_authrep.xml') or
         '/transactions/authrep.xml'
end

local function auth_path(using_oauth)
  return (using_oauth and '/transactions/oauth_authorize.xml') or
         '/transactions/authorize.xml'
end

local report_path = '/transactions.xml'

local function create_token_path(service_id)
  return format('/services/%s/oauth_access_tokens.xml', service_id)
end

-- Returns the authorize options that 3scale backend accepts. Those options
-- are specified via headers:
--  - rejection_reason_header: asks backend to return why a call is denied
--    (limits exceeded, application key invalid, etc.)
--  - no_body: when enabled, backend will not return a response body. The
--    body has many information like metrics, limits, etc. This information is
--    parsed only when using oauth native (not OIDC).
--    By enabling this option will save some work to the 3scale backend and
--    reduce network traffic.
--  - limit_headers: when enabled and the request is rate-limited, backend
--    returns the number of seconds remaining until the limit expires. It
--    returns -1 when there are no limits. With this header, backend returns
--    more information but we do not need it for now.
-- For the complete specs check:
-- https://github.com/3scale/apisonator/blob/master/docs/extensions.md
local function authorize_options(using_oauth_native)
  local headers = { ['3scale-options'] = 'rejection_reason_header=1&limit_headers=1' }

  if not using_oauth_native then
    headers['3scale-options'] = headers['3scale-options'] .. '&no_body=1'
  end

  return { headers = headers }
end

local function add_transaction(transactions, index, cred_type, cred, reports)
  local index_with_cred = format('transactions[%s][%s]', index, cred_type)
  transactions[index_with_cred] = cred

  for metric, value in pairs(reports) do
    local index_with_metric = format('transactions[%s][usage][%s]', index, metric)
    transactions[index_with_metric] = value
  end
end

local function format_transactions(reports_batch)
  local res = {}

  -- Note: A service only supports one kind of credentials
  local credentials_type = reports_batch.credentials_type
  local reports = reports_batch.reports

  local transaction_index = 0
  for credential, metrics in pairs(reports) do
    add_transaction(res, transaction_index, credentials_type, credential, metrics)
    transaction_index = transaction_index + 1
  end

  return res
end

-- This is a temporary fix.
-- We know that auths are idempotent so they can be retried safely when there
-- is an error caused by the 3scale backend closing the connection.
-- In the future, we should probably include the logic for retries in the
-- different backends of the http ng libs.
-- This only works with the "resty" backend because the "ngx" has its own logic
-- for retrying.
local function retry_auth(auth_resp, http_backend)
  return http_backend == http_ng_resty and
         auth_resp.status == 0 and
         auth_resp.error == "closed"
end

--- Call authrep (oauth_authrep) on backend.
-- @tparam ?{table,...} query list of query parameters
-- @treturn http_ng.response http response
function _M:authrep(...)
  if not self then
    return nil, 'not initialized'
  end

  local using_oauth = self.version == 'oauth'
  local auth_uri = authrep_path(using_oauth)
  local res = call_backend_transaction(
    self, auth_uri, authorize_options(self.uses_oauth_native), ...
  )

  inc_metrics('authrep', res.status)

  return res
end

--- Call authorize (oauth_authorize) on backend.
-- @tparam ?{table,...} query list of query parameters
-- @treturn http_ng.response http response
function _M:authorize(...)
  if not self then
    return nil, 'not initialized'
  end

  local using_oauth = self.version == 'oauth'
  local auth_uri = auth_path(using_oauth)
  local res = call_backend_transaction(
    self, auth_uri, authorize_options(self.uses_oauth_native), ...
  )

  if retry_auth(res, self.http_client.backend) then
    res = call_backend_transaction(
      self, auth_uri, authorize_options(self.uses_oauth_native), ...
    )
  end

  inc_metrics('auth', res.status)

  return res
end

function _M:report(reports_batch)
  local http_client = self.http_client

  local report_uri = build_url(self, report_path)
  local report_body = format_transactions(reports_batch)
  local res = http_client.post(report_uri, report_body)

  inc_metrics('report', res.status)

  return res
end

--- Calls backend to create an oauth token.
-- @tparam ?{table, ...} list of query params (might include the token, ttl,
--   app_id, and user_id)
-- @treturn http_ng.response http response
function _M:store_oauth_token(token_info)
  local http_client = self.http_client

  if not http_client then
    return nil, 'not initialized'
  end

  local url = build_url(self, create_token_path(self.service_id))
  return http_client.post(url, token_info)
end

return _M
