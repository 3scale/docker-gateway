local _M = {}

local mt = { __index = _M }

function _M.new(initial_value)
  local self = setmetatable({}, mt)
  self.value = tonumber(initial_value) or 0
  return self
end

function _M:increment(delta)
    self.value = self.value + (tonumber(delta) or 1)
    return self.value
end

function _M:decrement(delta)
    self.value = self.value - (tonumber(delta) or 1)
    return self.value
end

function _M:__tostring()
    return tostring(self.value)
end

return _M
