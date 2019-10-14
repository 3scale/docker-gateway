--- Mapping rules matcher
-- @module mapping_rules_matcher
-- Matches a request against a set of mapping rules and calculates the usage
-- that needs to be authorized and reported according to the rules that match.

local ipairs = ipairs
local insert = table.insert
local Usage = require('apicast.usage')

local _M = {}

--- Calculate usage from matching mapping rules.
-- Matches a request against a set of mapping rules and returns the resulting
-- usage and the matched rules.
-- @tparam string method HTTP method.
-- @tparam string uri URI.
-- @tparam table args Request arguments.
-- @tparam table rules Mapping rules to be matched.
-- @treturn Usage Calculated usage.
-- @treturn table Matched rules.
function _M.get_usage_from_matches(method, uri, args, rules)
  local usage = Usage.new()
  local matched_rules = {}

  for _, rule in ipairs(rules) do
    if rule:matches(method, uri, args) then
      -- Some rules have no delta. Send 0 in that case.
      usage:add(rule.system_name, rule.delta or 0)
      insert(matched_rules, rule)

      if rule.last then break end
    end
  end

  return usage, matched_rules
end

--- Check if there is a mapping rule that matches.
-- @tparam string method HTTP method.
-- @tparam string uri URI.
-- @tparam table args Request arguments.
-- @tparam table rules Mapping rules to be matched.
-- @treturn boolean Whether there is a match.
-- @treturn integer|nil Index of the first matched rule.
function _M.matches(method, uri, args, rules)
  for i, rule in ipairs(rules) do
    if rule:matches(method, uri, args) then
      return true, i
    end
  end

  return false
end

function _M.clean_usage_by_owner_id(rules, owner_id)
  local usage = Usage.new()
  if not owner_id then
      return usage
  end

  for _, rule in ipairs(rules) do
    -- Checking that the rule has owner_id, if it does not have owner_id means
    -- that does not belongs to a backendAPI.
    if rule.owner_id and owner_id ~= rule.owner_id then
      usage:add(rule.system_name, 0 - (rule.delta or 0))
    end
  end

  return usage
end

return _M
