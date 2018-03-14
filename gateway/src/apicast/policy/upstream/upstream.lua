--- Upstream policy
-- This policy allows to modify the host of a request based on its path.

local resty_resolver = require('resty.resolver')
local resty_url = require('resty.url')
local format = string.format
local ipairs = ipairs
local match = ngx.re.match
local table = table

local balancer = require('apicast.balancer')

local _M = require('apicast.policy').new('Upstream policy')

local new = _M.new

local function proxy_pass(url)
  local res = format('%s://upstream%s', url.scheme, url.path or '')

  local args = ngx.var.args
  if url.path and args then
    res = format('%s?%s', res, args)
  end

  return res
end

local function change_upstream(url)
  ngx.ctx.upstream = resty_resolver:instance():get_servers(
    url.host, { port = url.port or resty_url.default_port(url.scheme) })

  ngx.var.proxy_pass = proxy_pass(url)
  ngx.req.set_header('Host', url.host)

  -- We need to check that the headers have not already been sent. They could
  -- have been sent in a different policy, for example.
  if not ngx.headers_sent then
    ngx.exec("@upstream")
  end
end

-- Parses the urls in the config so we do not have to do it on each request.
local function init_config(config)
  if not config or not config.rules then return {} end

  local res = {}

  for _, rule in ipairs(config.rules) do
    local parsed_url = resty_url.parse(rule.url)
    table.insert(res, { regex = rule.regex, url = parsed_url })
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

function _M:content(context)
  local req_uri = ngx.var.uri

  for _, rule in ipairs(self.rules) do
    if match(req_uri, rule.regex) then
      ngx.log(ngx.DEBUG, 'upstream policy uri: ', req_uri, ' regex: ', rule.regex, ' match: true')
      context.upstream_changed = true
      return change_upstream(rule.url)
    elseif ngx.config.debug then
      ngx.log(ngx.DEBUG, 'upstream policy uri: ', req_uri, ' regex: ', rule.regex, ' match: false')
    end
  end
end

function _M.balancer(_, context)
  if context.upstream_changed then
    balancer.call()
  end
end

return _M
