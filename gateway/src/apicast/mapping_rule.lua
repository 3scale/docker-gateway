--- Mapping rule
-- @module mapping_rule
-- A mapping rule consists of a pattern used to match requests. It also defines
-- a metric and a value that indicates how to increase the usage of a metric
-- when there is a match.

local setmetatable = setmetatable
local pairs = pairs
local error = error
local type = type
local format = string.format
local re_match = ngx.re.match
local insert = table.insert
local re_gsub = ngx.re.gsub

-- This is introduced by API as a product feature. There are two kinds of
-- mapping rules owner: `BackendAPI` that means that is used by API as a
-- product and `Proxy` that means that it's a normal mapping rule.
local BackendAPIconst = "BackendApi"

local _M = {
  any_method = "ANY"
}

local mt = { __index = _M }

local function hash_to_array(hash)
  local array = {}

  for k,v in pairs(hash or {}) do
    insert(array, { k, v })
  end

  return array
end

local function regexpify(pattern)
  -- some urls in APIAP uses double / that it's a valid url, but ngx.var.uri
  -- eliminates the duplicates, so mapping rule needs to remove the duplicates
  -- ones.
  pattern = re_gsub(pattern,[[\/\/+]], '/', 'oj')

  pattern = re_gsub(pattern, [[\?.*]], '', 'oj')
  -- dollar sign is escaped by another $, see https://github.com/openresty/lua-nginx-module#ngxresub
  pattern = re_gsub(pattern, [[\{.+?\}]], [[([\w-.~%!$$&'()*+,;=@:]+)]], 'oj')
  pattern = re_gsub(pattern, [[\.]], [[\.]], 'oj')
  return pattern
end

local regex_variable = '\\{[-\\w_]+\\}'

local function matches_querystring_params(params, args)
  local match = true

  for i=1, #params do
    local param = params[i][1]
    local expected = params[i][2]
    local m, err = re_match(expected, regex_variable, 'oj')
    local value = args[param]

    if m then
      if not value then -- regex variable have to have some value
        ngx.log(ngx.DEBUG, 'check query params ', param,
          ' value missing ', expected)
        match = false
        break
      end
    else
      if err then ngx.log(ngx.ERR, 'check match error ', err) end

      -- if many values were passed use the last one
      if type(value) == 'table' then
        value = value[#value]
      end

      if value ~= expected then -- normal variables have to have exact value
        ngx.log(ngx.DEBUG, 'check query params does not match ',
          param, ' value ' , value, ' == ', expected)
        match = false
        break
      end
    end
  end

  return match
end

local function matches_uri(rule_pattern, uri)
  return re_match(uri, format("^%s", rule_pattern), 'oj')
end

local function new(http_method, pattern, params, querystring_params, metric, delta, last, owner_id, owner_type)
  local self = setmetatable({}, mt)

  local querystring_parameters = hash_to_array(querystring_params)

  self.method = http_method
  self.pattern = pattern
  self.regexpified_pattern = regexpify(pattern)
  self.parameters = params
  self.system_name = metric or error('missing metric name of rule')
  self.delta = delta
  self.last = last or false

  if owner_type == BackendAPIconst then
    self.owner_id = owner_id
  end


  self.querystring_params = function(args)
    return matches_querystring_params(querystring_parameters, args)
  end

  return self
end

--- Initializes a mapping rule from a proxy rule of the service configuration.
--
-- @tparam table proxy_rule Proxy rule from the service configuration.
-- @tfield string http_method HTTP method (GET, POST, etc.).
-- @tfield string pattern Pattern used to match a request.
-- @tfield table parameters Parameters of the pattern.
-- @tfield table querystring_parameters Table with the params of the request
--         and its values.
-- @tfield string metric_system_name Name of the metric.
-- @tfield integer delta The usage of the metric will be increased by this
--         value.
-- @tfield boolean last When set to true, indicates that if the rule matches,
--         it should be the last one to match. In other words, if this rule
--         matches, the mapping rules matcher should not try to match the rules
--         placed after this one.
-- @treturn mapping_rule New mapping rule.
function _M.from_proxy_rule(proxy_rule)
  return new(
    proxy_rule.http_method,
    proxy_rule.pattern,
    proxy_rule.parameters,
    proxy_rule.querystring_parameters,
    proxy_rule.metric_system_name,
    proxy_rule.delta,
    proxy_rule.last,
    tonumber(proxy_rule.owner_id),
    proxy_rule.owner_type
  )
end

--- Checks if the mapping rule matches a given request method, URI, and args
--
-- @tparam string method HTTP method (GET, POST, etc.).
-- @tparam string uri URI of an HTTP request.
-- @tparam table args Table with the args and values of an HTTP request.
-- @treturn boolean Whether the mapping rule matches the given request.
function _M:matches(method, uri, args)
  local match = (self.method == self.any_method or self.method == method) and
      matches_uri(self.regexpified_pattern, uri) and
      self.querystring_params(args)

  -- match can be nil. Convert to boolean.
  return match == true
end

return _M
