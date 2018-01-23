-- This is a simple policy. It allows you reject incoming requests with a
-- specified status code and message.
-- It's useful for maintance periods or to temporarily block an API

local _M = require('apicast.policy').new('Maintenance mode', '1.0.0')

local tonumber = tonumber
local new = _M.new


function _M.new(configuration)
  local policy = new(configuration)

  -- Set some default values
  policy.status_code = 503
  policy.message = "503 Service Unavailable - Maintenance"

  if configuration then
    policy.status_code = tonumber(configuration.status) or policy.status_code
    policy.message = configuration.message or policy.message
  end

  return policy
end

function _M:access()

  local status = self.status_code
  local msg = self.message

  ngx.status = status
  ngx.say(msg)

  return ngx.exit(ngx.status)
end

return _M
