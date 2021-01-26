local re_gsub = ngx.re.gsub
local re_match = ngx.re.match
local re_gmatch = ngx.re.gmatch
local re_split = require('ngx.re').split
local insert = table.insert
local format = string.format
local ipairs = ipairs
local setmetatable = setmetatable

local _M = {}

local mt = { __index = _M }

local function split(string, separator, max_matches)
  return re_split(string, separator, 'oj', nil, max_matches)
end

-- Returns a list of named args extracted from a match_rule.
-- For example, for the rule /{abc}/{def}?{ghi}=1, it returns this list:
-- { "{abc}", "{def}", "{ghi}" }.
--
-- Notice that each named arg is wrapped between "{" and "}". That's because
-- we always need to match those "{}", so we can add them here and avoid
-- string concatenations later.
local function extract_named_args(match_rule)
  local iterator, err = re_gmatch(match_rule, [[\{(.+?)\}]], 'oj')

  if not iterator then
    return nil, err
  end

  local named_args = {}

  while true do
    local m, err_iter = iterator()
    if err_iter then
      return nil, err_iter
    end

    if not m then
      break
    end

    insert(named_args, format('{%s}', m[1]))
  end

  return named_args
end

-- Rules contain {} for named args. This function replaces those with "()" to
-- be able to capture those args when matching the regex.
local function transform_rule_to_regex(match_rule)
  return re_gsub(
    match_rule,
    [[\{.+?\}]],
    [[([\w-.~%!$$&'()*+,;=@:]+)]], -- Same as in the MappingRule module
    'oj'
  )
end

-- Transforms a string representing the args of a query like:
-- "a=1&b=2&c=3" into 2 tables one with the arguments, and
-- another with the values:
-- { 'a', 'b', 'c' } and { '1', '2', '3' }.
local function string_params_to_tables(string_params)
  if not string_params then return {}, {} end

  local args = {}
  local values = {}

  local params_split = split(string_params, '&', 2)

  for _, param in ipairs(params_split) do
    local parts = split(param, '=', 2) -- avoid unpack, not jitted.
    insert(args, parts[1])
    insert(values, parts[2])
  end

  return args, values
end

local function replace_in_template(args, vals, template)
  local res = template

  for i = 1, #args do
    res = re_gsub(res, args[i], vals[i], 'oj')
  end

  return res
end

local function uri_and_params_from_template(template)
  local parts = split(template, [[\?]], 2) -- avoid unpack, not jitted.
  return parts[1], parts[2]
end

--- Initialize a NamedArgsMatcher
-- @tparam string match_rule Rule to be matched and that contains named args
--   with "{}". For example: "/{var_1}/something/{var_2}".
-- @tparam string template Template in which the named args matched will be
--   replaced. For example: "/v2/something/{var_1}?my_arg={var_2}".
function _M.new(match_rule, template, methods)
  local self = setmetatable({}, mt)

  self.named_args = extract_named_args(match_rule)
  self.regex_rule = transform_rule_to_regex(match_rule)
  self.template = template
  self.methods = methods

  return self
end

-- Returns true if the Method of the request is in the methods of the command meaning the rewrite rule should be applied
-- Returns true if no Method is provided in the config for backwardscompatibility
local function is_match_methods(methods)

  if methods == nil or next(methods) == nil  then
    return true
  end

  local request_method = ngx.req.get_method()

  for _,v in pairs(methods) do
    if v == request_method then
      return true
    end
  end
  return false
end

--- Match a path
-- @tparam string path The path of the URL
-- @treturn boolean True if there's a match, false otherwise
-- @treturn string The new path. If there's a match
-- @treturn table The new args. If there's a match
-- @treturn table The new values for the args. If there's a match.
-- Note: this method generates a new url and new query args when there is a
-- match, but does not modify the current ones.
-- Note: this method returns in separate tables the query args and their values
-- this is so callers can iterate through them with pairs (jitted) instead of
-- ipairs (non-jitted).
function _M:match(path)

  if not is_match_methods(self.methods) then
    return false
  end

  local matches = re_match(path, self.regex_rule, 'oj')

  if not matches or #self.named_args ~= #matches then
    return false
  end

  local replaced_template = replace_in_template(
    self.named_args, matches, self.template)

  local uri, raw_params = uri_and_params_from_template(replaced_template)

  local params, vals = string_params_to_tables(raw_params)

  return true, uri, params, vals
end

return _M
