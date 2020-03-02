--- hosts load balancer policy
-- This policy allows to specify several upstrams and enable load balancing on them.

local Upstream = require('apicast.upstream')
local ipairs = ipairs
local tab_new = require('resty.core.base').new_tab
local balancer = require('apicast.balancer')

local hostSelector = 0
local rulesSize = 0

local _M = require('apicast.policy').new('Hostloadb policy', 'builtin')
local new = _M.new

-- Parses the urls in the config so we do not have to do it on each request.
local function init_config(config)
  if not config or not config.rules then return tab_new(0, 0) end

  local res = {}
  local index = 0

  for _, rule in ipairs(config.rules) do
    local upstream, err = Upstream.new(rule.url)
    if upstream then
      res[index] = rule.url
      index = index + 1
    else
      ngx.log(ngx.WARN, 'failed to initialize upstream from url: ', rule.url, ' err: ', err)
    end
  end

  rulesSize = index
  return res
end

--- Initialize an upstream policy.
-- @tparam[opt] table config Contains the host rewriting rules.
-- Each rule consists of:
--   - url: new url.
function _M.new(config)
  local self = new(config)
  self.rules = init_config(config)
  return self
end

--- Round robin load balancing
function _M:rewrite(context)
  local req_uri = ngx.var.uri
  context[self] = Upstream.new(self.rules[hostSelector])
  hostSelector = (hostSelector + 1) % rulesSize
end

function _M:content(context)
  local upstream = context[self]
  if upstream then
    upstream:call(context)
  else
    return nil, 'no upstream'
  end
end

_M.balancer = balancer.call

return _M