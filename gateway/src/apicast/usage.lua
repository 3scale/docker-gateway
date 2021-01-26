--- Usage
-- @module usage
-- Usage to be authorized and reported against 3scale's backend.

local setmetatable = setmetatable
local ipairs = ipairs
local insert = table.insert
local remove = table.remove
local encode_args = ngx.encode_args

local _M = {}

local mt = { __index = _M }

--- Initialize a usage.
-- @return usage New usage.
function _M.new()
  local self = setmetatable({}, mt)

  -- table where the keys are metrics and the values their deltas.
  self.deltas = {}

  -- table that contains the metrics that have a delta associated.
  -- It's useful to iterate over the deltas without using '.pairs'.
  -- That's what we are doing in .merge().
  -- We want to avoid using '.pairs' because is not jitted, '.ipairs' is.
  self.metrics = {}

  return self
end

--- Add a metric usage.
-- Increases the usage of the given metric by the given value. If the metric
-- is not in the usage, it will be included.
-- Note that this mutates self.
-- @tparam string metric Metric.
-- @tparam integer value Value.
function _M:add(metric, value)
  if self.deltas[metric] then
    self.deltas[metric] = self.deltas[metric] + value
  else
    self.deltas[metric] = value
    insert(self.metrics, metric)
  end
end

-- Remove metric from the usage map.
-- Note that this mutates self.
-- @tparam string metrc Metric.
function _M:remove_metric(metric)
  local tablefind = function (tab,el)
    for index, value in pairs(tab) do
      if value == el then
        return index
      end
    end
  end

  remove(self.metrics, tablefind(self.metrics, metric))
  self.deltas[metric] = nil
end

--- Merge usages
-- Merges two usages. This means that:
--
-- 1) When a metric appears in both usages, its delta is updated in self by
--    adding the two values.
-- 2) When a metric does not appear in self, it is added in self.
--
-- 3) If the metric added is negative and the result is negative or 0, metric
-- will be deleted.
--
-- Note that this mutates self.
-- @tparam another_usage Usage Usage.
function _M:merge(another_usage)
  local another_usage_metrics = another_usage.metrics
  local another_usage_deltas = another_usage.deltas

  for _, metric in ipairs(another_usage_metrics) do
    local delta = another_usage_deltas[metric]
    self:add(metric, delta)

    if self.deltas[metric] <= 0 then
      self:remove_metric(metric)
    end
  end
end


-- Converts a usage to the format expected by the 3scale backend client.
function _M:format()
  local res = {}

  local usage_metrics = self.metrics
  local usage_deltas = self.deltas

  for _, metric in ipairs(usage_metrics) do
    local delta = usage_deltas[metric]
    res['usage[' .. metric .. ']'] = delta
  end

  return res
end

--- Return a string with the encoded format() output
function _M:encoded_format()
    return encode_args(self:format())
end

--- Return  the max delta in the usage, by default returns 0
function _M:get_max_delta()
    local max = 0

    for _,v in pairs(self.deltas or {}) do
        if v > max then
            max = v
        end
    end
    return max
end

return _M
