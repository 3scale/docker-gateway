local tonumber = tonumber

local prometheus = require('apicast.prometheus')

local _M = {}

local service_label = 'service'
local status_label = 'status'

local upstream_status_codes = prometheus(
  'counter',
  'upstream_status',
  'HTTP status from upstream servers',
  { status_label, service_label }
)

local upstream_resp_times = prometheus(
  'histogram',
  'upstream_response_time_seconds',
  'Response times from upstream servers',
  { service_label }
)

local function inc_status_codes_counter(status, service)
  if tonumber(status) and upstream_status_codes then
    upstream_status_codes:inc(1, { status, service })
  end
end

local function add_resp_time(response_time, service)
  local time = tonumber(response_time)

  if time and upstream_resp_times then
    upstream_resp_times:observe(time, { service })
  end
end

function _M.report(status, response_time, service)
  inc_status_codes_counter(status, service)
  add_resp_time(response_time, service)
end

return _M
