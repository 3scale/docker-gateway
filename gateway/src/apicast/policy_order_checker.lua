local setmetatable = setmetatable
local pairs = pairs
local ipairs = ipairs
local policy_loader = require 'apicast.policy_loader'
local insert = table.insert
local format = string.format

local _M = {}

local mt = { __index = _M }

-- The name that appears in the schema is different from the name in an
-- instance of a policy. The name of the schema corresponds to the name of the
-- folder that contains the policy ("headers", "routing"), whereas the name in
-- an instantiated policy is "prettified" ("Headers policy", "Routing policy").
--
-- In a policy chain, we only have access to the "prettified" names, so in
-- order to compare them, we'll need to convert them using this function.
local function prettified_name(name_in_schema)
  local policy_mod = policy_loader:pcall(name_in_schema)
  return policy_mod and policy_mod._NAME
end

local OrderRestrictions = {}

function OrderRestrictions.new()
  local self = setmetatable({}, { __index = OrderRestrictions })
  self.restrictions = {}
  return self
end

function OrderRestrictions.new_from_policy_manifests(policy_manifests)
  local self = OrderRestrictions.new()

  -- Notice that the value is an array because there might be several versions
  -- of a policy.
  for policy_name, manifests in pairs(policy_manifests) do
    for _, manifest in ipairs(manifests) do
      if manifest.order then
        local policy_in_manifest = {
          name = prettified_name(policy_name),
          version = manifest.version
        }

        for _, policy_in_restriction in ipairs(manifest.order.before or {}) do
          self:insert(
              policy_in_manifest,
              {
                name = prettified_name(policy_in_restriction.name),
                version = policy_in_restriction.version
              }
          )
        end

        for _, policy_in_restriction in ipairs(manifest.order.after or {}) do
          self:insert(
              {
                name = prettified_name(policy_in_restriction.name),
                version = policy_in_restriction.version
              },
              policy_in_manifest
          )
        end
      end
    end
  end

  return self
end

function OrderRestrictions:insert(policy_before, policy_after)
  self.restrictions[policy_before.name] = self.restrictions[policy_before.name] or {}
  self.restrictions[policy_before.name][policy_before.version] =
      self.restrictions[policy_before.name][policy_before.version] or {}

  insert(
      self.restrictions[policy_before.name][policy_before.version],
      policy_after
  )
end

function OrderRestrictions:policies_to_be_placed_after(policy_before)
  return (self.restrictions[policy_before.name] and
          self.restrictions[policy_before.name][policy_before.version]) or {}
end

function _M.new(policy_manifests)
  local self = setmetatable({}, mt)
  self.restrictions = OrderRestrictions.new_from_policy_manifests(policy_manifests)
  return self
end

-- Returns a table with policies and their positions in the chain.
-- Example of a chain with 4 policies:
-- ['some_policy']['1.0.0'] = { 1, 2 }
-- ['some_policy']['2.0.0'] = 3
-- ['another_policy']['builtin'] = 4
local function positions_in_the_chain(policy_chain)
  local res = {}

  for index, policy in ipairs(policy_chain) do
    local policy_name = policy._NAME
    local policy_version = policy._VERSION

    res[policy_name] = res[policy_name] or {}
    res[policy_name][policy_version] = res[policy_name][policy_version] or {}

    insert(res[policy_name][policy_version], index)
  end

  return res
end

local function error_msg(policy_before, policy_after)
  return format(
      "%s (version: %s) should be placed before %s (version: %s)",
      policy_before.name, policy_before.version,
      policy_after.name, policy_after.version
  )
end

-- Logs warnings when it detects that an order restriction has been violated in
-- the given policy chain.
function _M:check(policy_chain)
  if not policy_chain then return end

  local positions = positions_in_the_chain(policy_chain)

  for index, policy in ipairs(policy_chain) do
    local policy_name = policy._NAME
    local policy_version = policy._VERSION

    local policies_to_be_placed_after = self.restrictions:policies_to_be_placed_after(
        { name = policy_name, version = policy_version }
    )

    for _, policy_after in ipairs(policies_to_be_placed_after) do
      local indexes_should_be_after = (positions[policy_after.name] and
          positions[policy_after.name][policy_after.version]) or {}

      for _, index_after in ipairs(indexes_should_be_after) do
        if index > index_after then
          ngx.log(
              ngx.WARN,
              error_msg({ name = policy_name, version = policy_version }, policy_after)
          )
        end
      end
    end
  end
end

return _M
