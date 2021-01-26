local lrucache = require("resty.lrucache")
local cache_entry = require("apicast.policy.rate_limit_headers.cache_entry")

local _M = {}

local mt = { __index = _M }
local default_namespace = "rate_limit_namespace"


function _M.new(namespace)
  local self = setmetatable({}, mt)
  -- LRU cache used only for unittesting, where ngx.shared is not enabled.
  self.cache = ngx.shared.rate_limit_headers or lrucache.new(1)
  self.namespace = namespace or default_namespace
  return self
end

function _M:get_key(usage)
  return self.namespace .. "::".. usage:encoded_format()
end

function _M:decrement_usage_metric(usage)
    if not usage then
        return cache_entry.Init_empty(usage)
    end

    local key = self:get_key(usage)
    local raw_data = self.cache:get(key)
    if not raw_data then
        -- If it's here should not, because this should be called in the
        -- post_action, so return an empty one0
        return cache_entry.Init_empty(usage)
    end
    local data = cache_entry.import(usage, raw_data)

    data:decrement(1)
    self.cache:set(key, data:export())
    return data
end

function _M:reset_or_create_usage_metric(usage, max, remaining, reset)
    local key = self:get_key(usage)
    local data = cache_entry.new(usage, max, remaining, reset)
    self.cache:set(key, data:export())
    return data
end

return _M
