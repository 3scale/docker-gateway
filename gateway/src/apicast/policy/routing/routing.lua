local ipairs = ipairs
local tab_insert = table.insert
local tab_new = require('resty.core.base').new_tab

local balancer = require('apicast.balancer')
local UpstreamSelector = require('upstream_selector')
local Request = require('request')
local Rule = require('rule')

local _M = require('apicast.policy').new('Routing policy', 'builtin')

local new = _M.new

local function init_rules(config)
  if not config or not config.rules then return tab_new(0, 0) end

  local res = tab_new(#config.rules, 0)

  for _, config_rule in ipairs(config.rules) do
    local rule, err = Rule.new_from_config_rule(config_rule)

    if rule then
      tab_insert(res, rule)
    else
      ngx.log(ngx.WARN, err)
    end
  end

  return res
end

function _M.new(config)
  local self = new(config)
  self.upstream_selector = UpstreamSelector.new()
  self.rules = init_rules(config)
  return self
end

function _M:content(context)
  -- This should be moved to the place where the context is started, so other
  -- policies can use it.
  context.request = context.request or Request.new()

  -- Once request is in the context, we should move this to wherever the jwt is
  -- validated.
  context.request:set_validated_jwt(context.jwt)

  local upstream = self.upstream_selector:select(self.rules, context)

  if upstream then
    upstream:call(context)
  else
    return nil, 'no upstream'
  end
end

_M.balancer = balancer.call

return _M
