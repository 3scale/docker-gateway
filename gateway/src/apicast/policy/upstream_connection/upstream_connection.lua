-- Upstream Connection Policy
--- This policy exposes some parameters related with the connection to the
--- upstream.

local tonumber = tonumber

local _M = require('apicast.policy').new('Upstream connection policy', 'builtin')

local new = _M.new

function _M.new(config)
  local self = new(config)

  self.connect_timeout = tonumber(config.connect_timeout)
  self.send_timeout = tonumber(config.send_timeout)
  self.read_timeout = tonumber(config.read_timeout)

  return self
end

function _M:export()
  return {
    upstream_connection_opts = {
      connect_timeout = self.connect_timeout,
      send_timeout = self.send_timeout,
      read_timeout = self.read_timeout
    }
  }
end

return _M
