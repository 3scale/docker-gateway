local now = ngx.now
local _M = {}

local mt = { __index = _M }

function _M.new(limit_time_delta, initial_time)
  if not initial_time then
    initial_time = now()
  end

  local self = setmetatable({}, mt)
  self.limit_time = tonumber(initial_time) + tonumber(limit_time_delta)
  return self
end

function _M:remaining_secs(time)
  return self.limit_time - time
end

function _M:remaining_secs_positive(time)
  local result = self:remaining_secs(time)
  if result >= 0 then
    return tonumber(string.format("%i", result))
  end
  return 0
end

function _M:__tostring()
    return tostring(self.limit_time)
end

return _M
