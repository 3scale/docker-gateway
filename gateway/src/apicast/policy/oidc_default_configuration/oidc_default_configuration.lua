-- This is a oidc_default_configuration description.

local policy = require('apicast.policy')
local _M = policy.new('oidc_default_configuration')

local new = _M.new
--- Initialize a oidc_default_configuration
-- @tparam[opt] table config Policy configuration.
function _M.new(config)
  local self = new(config)

  if config then
    self.overrides = config.overrides
  end

  return self
end

function _M:rewrite(context)
  local overrides = self.overrides
  local oidc = context.service.oidc

  if oidc then
    local config = oidc.config

    if config then
      for _,override in ipairs(overrides) do
        config[override.key] = override.value
      end
    end
  end
end

return _M
