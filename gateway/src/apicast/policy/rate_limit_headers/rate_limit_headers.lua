local policy = require('apicast.policy')
local _M = policy.new('Rate Limit Headers', 'builtin')

local usage_cache = require "cache"
local math_max = math.max

local new = _M.new
local get_phase = ngx.get_phase

-- Headers returned by APISonator with the information.
-- https://github.com/3scale/apisonator/blob/master/docs/extensions.md#limit_headers-boolean
local threescale_limit_header = "3scale-Limit-Max-Value"
local threescale_remaining_header = "3scale-Limit-Remaining"
local threescale_reset_header = "3scale-Limit-Reset"

-- Headers spec in RFC
-- https://ioggstream.github.io/draft-polli-ratelimit-headers/draft-polli-ratelimit-headers.html#name-header-specifications
local limit_header = "RateLimit-Limit"
local remaining_header = "RateLimit-Remaining"
local reset_header = "RateLimit-Reset"

function _M.new(config)
  local self = new(config)
  self.cache = usage_cache.new("rate_limit_headers")
  return self
end

local function handler(self)
  local _self = self
  local callback = function(context, response)
    if not response.headers then
        -- This is why callback is called from batching policy, and only returns
        -- 200 status
        ngx.log(ngx.ERR, "No headers in reset rate limit headers, discard")
        return nil
    end
    local limit = response.headers[threescale_limit_header] or 0
    local remaining = response.headers[threescale_remaining_header] or 0
    local reset = response.headers[threescale_reset_header] or 0

    local data =  _self.cache:reset_or_create_usage_metric(
        context.usage, limit, remaining, reset)

    if get_phase() == "access" then
        context.rate_limit_info = data
    end
  end
  return callback
end

function _M:access(context)
    context:add_backend_auth_subscriber(handler(self))
end

local function decrement(self, usage)
    return self.cache:decrement_usage_metric(usage)
end

-- return 0 if the number is negative
local function positive_number(number)
  return math_max(tonumber(number), 0)
end

local function add_headers(info)
    if info.reset <= 0 then
      -- filter is not defined at all, so skip it
      return nil
    end
    ngx.header[limit_header] = positive_number(info.limit)
    ngx.header[remaining_header] = positive_number(info.remaining)
    ngx.header[reset_header] = info.reset
end

function _M:content(context)
    if context.rate_limit_info then
        add_headers(context.rate_limit_info:dump_data())
    else
        add_headers(decrement(self, context.usage):dump_data())
    end
end

return _M
