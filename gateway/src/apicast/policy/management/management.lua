-- This is a management description.

local policy = require('apicast.policy')
local _M = policy.new('management')

local management = require('apicast.management')

local new = _M.new
--- Initialize a management
-- @tparam[opt] table config Policy configuration.
function _M.new(config)
  local self = new(config)

  local router = management.router(config and config.mode)

  if not router then
    return nil, 'invalid management api'
  end

  self.router = router

  return self
end

function _M:content()
  local method = ngx.req.get_method()
  local uri = ngx.var.uri

  local ok, err = self.router:execute(method, uri)

  if not ok then
    ngx.status = 404
  end

  if err then
    ngx.say(err)
  end
end

return _M
