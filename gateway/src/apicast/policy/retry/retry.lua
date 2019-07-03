--- Retry policy

local tonumber = tonumber

local _M = require('apicast.policy').new('Retry Policy', 'builtin')

local new = _M.new


function _M.new(config)
  local self = new(config)
  self.retries = tonumber(config.retries)
  return self
end

function _M:export()
  return { upstream_retries = self.retries }
end

return _M
