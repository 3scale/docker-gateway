local error = error

local _M = require('apicast.policy').new('error_policy', '1.0.0')

function _M.new()
  error()
end

function _M.rewrite()
  error()
end

return _M
