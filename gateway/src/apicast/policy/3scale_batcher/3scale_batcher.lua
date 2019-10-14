local backend_client = require('apicast.backend_client')
local AuthsCache = require('auths_cache')
local ReportsBatcher = require('reports_batcher')
local keys_helper = require('keys_helper')
local policy = require('apicast.policy')
local errors = require('apicast.errors')
local reporter = require('reporter')
local Transaction = require('transaction')
local http_ng_resty = require('resty.http_ng.backend.resty')
local semaphore = require('ngx.semaphore')
local TimerTask = require('resty.concurrent.timer_task')

local metrics = require('apicast.policy.3scale_batcher.metrics')

local ipairs = ipairs

local default_auths_ttl = 10
local default_batch_reports_seconds = 10

local _M, mt = policy.new('3scale Batcher policy', 'builtin')

local new = _M.new

mt.__gc = function(self)
  -- Instances of this policy are garbage-collected when the config is
  -- reloaded. We need to ensure that the TimerTask instance schedules another
  -- run before that so we do not leave any pending reports.

  if self.timer_task then
    self.timer_task:cancel(true)
  end
end

function _M.new(config)
  local self = new(config)

  local auths_ttl = config.auths_ttl or default_auths_ttl
  self.auths_cache = AuthsCache.new(ngx.shared.cached_auths, auths_ttl)

  self.reports_batcher = ReportsBatcher.new(
    ngx.shared.batched_reports, 'batched_reports_locks')

  self.batch_reports_seconds = config.batch_report_seconds or
                               default_batch_reports_seconds

  -- Semaphore used to ensure that only one TimerTask is started per worker.
  local semaphore_report_timer, err = semaphore.new(1)
  if not semaphore_report_timer then
    ngx.log(ngx.ERR, "Create semaphore failed: ", err)
  end
  self.semaphore_report_timer = semaphore_report_timer

  -- Cache for authorizations to be used in the event of a 3scale backend
  -- downtime.
  -- This cache allows us to use this policy in combination with the caching
  -- one.
  self.backend_downtime_cache = ngx.shared.api_keys

  return self
end

-- TODO: More policies are using this method. Move it to backend_client to
-- avoid duplicating code.
-- Converts a usage to the format expected by the 3scale backend client.
local function format_usage(usage)
  local res = {}

  local usage_metrics = usage.metrics
  local usage_deltas = usage.deltas

  for _, metric in ipairs(usage_metrics) do
    local delta = usage_deltas[metric]
    res['usage[' .. metric .. ']'] = delta
  end

  return res
end

local function set_flag_to_avoid_auths_in_apicast(context)
  context.skip_apicast_access = true
end

local function report(service_id, backend, reports_batcher)
  local reports = reports_batcher:get_all(service_id)

  if reports then
    ngx.log(ngx.DEBUG, '3scale batcher report timer got ', #reports, ' reports')
  end

  -- TODO: verify if we should limit the number of reports sent in a sigle req
  reporter.report(reports, service_id, backend, reports_batcher)
end

local function timer_task(self, service_id, backend)
  local task = report

  local task_options = {
    args = { service_id, backend, self.reports_batcher },
    interval = self.batch_reports_seconds
  }

  return TimerTask.new(task, task_options)
end

-- This starts a TimerTask on each worker.
-- Starting a TimerTask on each worker means that there will be more calls to
-- 3scale backend, and the config param 'batch_report_seconds' becomes
-- more confusing because the reporting frequency will be affected by the
-- number of APIcast workers.
-- If we started a TimerTask just on one of the workers, it could die, and then,
-- there would not be any reporting.
local function ensure_timer_task_created(self, service_id, backend)
  local check_timer_task = self.semaphore_report_timer:wait(0)

  if check_timer_task then
    if not self.timer_task then
      self.timer_task = timer_task(self, service_id, backend)

      self.timer_task:execute()

      ngx.log(ngx.DEBUG, 'scheduled 3scale batcher report timer every ',
                         self.batch_reports_seconds, ' seconds')
    end

    self.semaphore_report_timer:post()
  end
end

local function rejection_reason_from_headers(response_headers)
  return response_headers and response_headers['3scale-rejection-reason']
end

local function error(service, rejection_reason)
  if rejection_reason == 'limits_exceeded' then
    return errors.limits_exceeded(service)
  else
    return errors.authorization_failed(service)
  end
end

local function update_downtime_cache(cache, transaction, backend_status, cache_handler)
  local key = keys_helper.key_for_cached_auth(transaction)
  cache_handler(cache, key, { status = backend_status })
end

local function handle_backend_ok(self, transaction, cache_handler)
  if cache_handler then
    update_downtime_cache(self.backend_downtime_cache, transaction, 200, cache_handler)
  end

  self.auths_cache:set(transaction, 200)
  self.reports_batcher:add(transaction)
end

local function handle_backend_denied(self, service, transaction, status, headers, cache_handler)
  if cache_handler then
    update_downtime_cache(self.backend_downtime_cache, transaction, status, cache_handler)
  end

  local rejection_reason = rejection_reason_from_headers(headers)
  self.auths_cache:set(transaction, status, rejection_reason)
  return error(service, rejection_reason)
end

local function handle_backend_error(self, service, transaction, cache_handler)
  local key = keys_helper.key_for_cached_auth(transaction)
  local cached = cache_handler and self.backend_downtime_cache:get(key)

  if cached == 200 then
    self.reports_batcher:add(transaction)
  else
    -- The caching policy does not store the rejection reason, so we can only
    -- return a generic error.
    return error(service)
  end
end

local function handle_cached_auth(self, cached_auth, service, transaction)
  if cached_auth.status == 200 then
    self.reports_batcher:add(transaction)
  else
    return error(service, cached_auth.rejection_reason)
  end
end

function _M.rewrite(_, context)
  -- The APIcast policy reads this flag in the access phase.
  -- That's why we need to set it before that phase. If we set it in access()
  -- and placed the APIcast policy before the batcher in the chain, APIcast
  -- would read the flags before the batcher set them, and both policies would
  -- report to the 3scale backend.
  set_flag_to_avoid_auths_in_apicast(context)
end

-- Note: when an entry in the cache expires, there might be several requests
-- with those credentials and all of them will call auth() on backend with the
-- same parameters until the auth status is cached again. In the future, we
-- might want to introduce a mechanism to avoid this and reduce the number of
-- calls to backend.
function _M:access(context)
  local backend = backend_client:new(context.service, http_ng_resty)
  local usage = context.usage

  -- If routing policy changes the upstream and it only belongs to a specified
  -- owner, we need to filter out the usage for APIs that are not used at all.
  if context.route_upstream_usage_cleanup then
    context:route_upstream_usage_cleanup(usage, ngx.ctx.matched_rules)
  end

  local service = context.service
  local service_id = service.id
  local credentials = context.credentials
  local transaction = Transaction.new(service_id, credentials, usage)

  ensure_timer_task_created(self, service_id, backend)

  local cached_auth = self.auths_cache:get(transaction)
  local auth_is_cached = (cached_auth and true) or false
  metrics.update_cache_counters(auth_is_cached)

  if cached_auth then
    handle_cached_auth(self, cached_auth, service, transaction)
  else
    local formatted_usage = format_usage(usage)
    local backend_res = backend:authorize(formatted_usage, credentials)
    local backend_status = backend_res.status
    local cache_handler = context.cache_handler -- Set by Caching policy

    if backend_status == 200 then
      handle_backend_ok(self, transaction, cache_handler)
    elseif backend_status >= 400 and backend_status < 500 then
      handle_backend_denied(
        self, service, transaction, backend_status, backend_res.headers, cache_handler)
    else
      handle_backend_error(self, service, transaction, cache_handler)
    end
  end
end

return _M
