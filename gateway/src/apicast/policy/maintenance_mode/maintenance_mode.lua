-- This policy allows to reject incoming requests with a
-- specified status code and message.
-- It's useful for maintenance periods or to temporarily block an API

local _M = require('apicast.policy').new('Maintenance mode', 'builtin')

local tonumber = tonumber
local new = _M.new

local default_status_code = 503
local default_message = "Service Unavailable - Maintenance"
local default_message_content_type = "text/plain; charset=utf-8"

local Condition = require('apicast.conditions.condition')
local Operation = require('apicast.conditions.operation')
local Upstream = require('apicast.upstream')

local string = require('string')
local resty_url = require('resty.url')

function _M.new(configuration)
  local policy = new(configuration)

  policy.status_code = default_status_code
  policy.message = default_message
  policy.message_content_type = default_message_content_type

  if configuration then
    policy.maintenance_upstreams = configuration.upstreams
    policy.status_code = tonumber(configuration.status) or policy.status_code
    policy.message = configuration.message or policy.message
    policy.message_content_type = configuration.message_content_type or policy.message_content_type
  end

  policy:load_condition(configuration)
  return policy
end

function _M:load_condition(config)
  if not config or not config.condition then
    return
  end

  local operations = {}
  for _, operation in ipairs(config.condition.operations or {}) do
    table.insert( operations,
      Operation.new(
        operation.match, operation.match_type,
        operation.op,
        operation.value, operation.value_type or default_template_type))
  end
  self.condition = Condition.new( operations, config.condition.combine_op or default_combine_op)
end

local function maintenance_mode(policy)
  ngx.log(ngx.DEBUG, 'Maintenance mode enabled for this request')
  ngx.header['Content-Type'] = policy.message_content_type
  ngx.status = policy.status_code
  ngx.say(policy.message)
  return ngx.exit(ngx.status)
end

local function uris_match(uri1, uri2)
  local scheme1 = uri1.scheme or "http"
  local scheme2 = uri2.scheme or "http"
  local port1 = uri1.port or port1
  if not port1 then
    port1 = (scheme1 == "https" and 443 or 80)
  end
  local port2 = uri2.port or port2
  if not port2 then
    port2 = (scheme2 == "https" and 443 or 80)
  end

  local path1 = uri1.path or ""
  path1 = string.gsub(path1, "/$", "")
  local path2 = uri2.path or ""
  path2 = string.gsub(path2, "/$", "")

  return scheme1 == scheme2 and uri1.host == uri2.host and port1 == port2 and path1 == path2 
end

local function fix_url(url)
  url = string.gsub(url, "%s+", "") 
  return string.find(url, '^http') and url or "http://"..url
end

local function maintenance_logic(policy, context, upstream_uri)
  if policy.condition and not policy.condition:evaluate(context) then
    return
  end

  if not policy.maintenance_upstreams or next(policy.maintenance_upstreams) == nil then
    maintenance_mode(policy)
    return
  end
  for _, maintenance_upstream in ipairs(policy.maintenance_upstreams) do
    maintenance_upstream.url = fix_url(maintenance_upstream.url)
    local parsed_uri = resty_url.parse(maintenance_upstream.url)
    
    if parsed_uri and uris_match(parsed_uri, upstream_uri) then
      maintenance_mode(policy)
      return
    end
  end
end

--route_upstream is set by the policies that can customize the upstream URL (routing, upstream)
--otherwise this falls back to the upstream configured in the proxy config object
function _M:access(context)
  local upstream_uri
  local proxy_upstream = context.route_upstream or Upstream.new(context.service.api_backend)
  
  if proxy_upstream then
    upstream_uri = proxy_upstream.uri
  else
    ngx.log(ngx.DEBUG, 'Upstream not found')
    return
  end

  maintenance_logic(self, context, upstream_uri)
end

return _M

