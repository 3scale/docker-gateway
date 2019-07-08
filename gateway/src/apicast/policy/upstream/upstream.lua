--- Upstream policy
-- This policy allows to modify the host of a request based on its path.

local Upstream = require('apicast.upstream')
local ipairs = ipairs
local match = ngx.re.match
local tab_insert = table.insert
local tab_new = require('resty.core.base').new_tab
local balancer = require('apicast.balancer')

local _M = require('apicast.policy').new('Upstream policy', 'builtin')

local new = _M.new

-- Parses the urls in the config so we do not have to do it on each request.
local function init_config(config)
  if not config or not config.rules then return tab_new(0, 0) end

  local res = tab_new(#config.rules, 0)

  for _, rule in ipairs(config.rules) do
    local upstream, err = Upstream.new(rule.url)

    if upstream then
      tab_insert(res, { regex = rule.regex, url = rule.url })
    else
      ngx.log(ngx.WARN, 'failed to initialize upstream from url: ', rule.url, ' err: ', err)
    end
  end

  return res
end

--- Initialize an upstream policy.
-- @tparam[opt] table config Contains the host rewriting rules.
-- Each rule consists of:
--
--   - regex: regular expression to be matched.
--   - url: new url in case of match.
function _M.new(config)
  local self = new(config)
  self.rules = init_config(config)
  return self
end

function _M:rewrite(context)
  local req_uri = ngx.var.uri

  for _, rule in ipairs(self.rules) do
    if match(req_uri, rule.regex) then
      ngx.log(ngx.DEBUG, 'upstream policy uri: ', req_uri, ' regex: ', rule.regex, ' match: true')
      -- better to allocate new object for each request as it is going to get mutated
      context[self] = Upstream.new(rule.url)
      break
    else
      ngx.log(ngx.DEBUG, 'upstream policy uri: ', req_uri, ' regex: ', rule.regex, ' match: false')
    end
  end
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
