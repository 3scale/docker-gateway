--- Logging policy

local _M  = require('apicast.policy').new('Logging Policy', 'builtin')

local new = _M.new

local default_enable_access_logs = true

-- Defined in ngx.conf.liquid and used in the 'access_logs' directive.
local ngx_var_access_logs_enabled = 'access_logs_enabled'

-- Returns the value for the ngx var above from a boolean that indicates
-- whether access logs are enabled or not.
local val_for_ngx_var ={
  [true] = '1',
  [false] = '0'
}

function _M.new(config)
  local self = new(config)

  local enable_access_logs = config.enable_access_logs
  if enable_access_logs == nil then -- Avoid overriding when it's false.
    enable_access_logs = default_enable_access_logs
  end

  if not enable_access_logs then
    ngx.log(ngx.DEBUG, 'Disabling access logs')
  end

  self.enable_access_logs_val = val_for_ngx_var[enable_access_logs]

  return self
end

function _M:log()
  ngx.var[ngx_var_access_logs_enabled] = self.enable_access_logs_val
end

return _M
