local _M  = require('apicast.policy').new('On failed', 'builtin')
local new = _M.new


function _M.new(config)
  local self = new(config)
  self.error_status_code = config.error_status_code or ngx.HTTP_SERVICE_UNAVAILABLE
  return self
end

function _M:export()
  return {
    policy_error_callback = function(policy_name, error_message)
      ngx.log(ngx.DEBUG, "Stop request because policy: '", policy_name, "' failed, error='", error_message, "'")
      ngx.exit(self.error_status_code)
    end
  }
end

return _M
