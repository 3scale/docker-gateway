local policy = require('apicast.policy')
local _M = policy.new('HTTP Code Overwrite', 'builtin')
local ipairs = ipairs
local new = _M.new

function _M.new(config)
    local self = new(config)
    self.http_statuses = {}
    for _, code in ipairs(config.http_statuses or {}) do
        self.http_statuses[code.upstream] = code.apicast
    end
    return self
  end

function _M:header_filter()
  ngx.status = self.http_statuses[ngx.status] or ngx.status
end

return _M
