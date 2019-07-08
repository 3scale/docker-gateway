--- PolicyChain module
-- A policy chain is simply a sorted list of policies. The policy chain
-- defines a method for each one of the nginx phases (rewrite, access, etc.).
-- Each of those methods simply calls the same method on each of the policies
-- of the chain that implement that method. The calls are made following the
-- order that the policies have in the chain.

local setmetatable = setmetatable
local error = error
local rawset = rawset
local type = type
local ipairs = ipairs
local require = require
local insert = table.insert
local sub = string.sub
local format = string.format
local pcall = pcall
local noop = function() end

require('apicast.loader')

local linked_list = require('apicast.linked_list')
local policy_phases = require('apicast.policy').phases
local policy_loader = require('apicast.policy_loader')
local PolicyOrderChecker = require('apicast.policy_order_checker')
local policy_manifests_loader = require('apicast.policy_manifests_loader')

local _M = {

}

local mt = {
    __index = _M,
    __newindex = function(t, k ,v)
        if t.frozen then
            error("readonly table")
        else
            rawset(t, k, v)
        end
    end
}

--- Build a policy chain
-- Builds a new policy chain from a list of modules representing policies.
-- If no modules are given, 'apicast' will be used.
-- @tparam table modules Each module can be a string or an object. If the
--  module is a string, the result of require(module).new() will be added to
--  the chain. If it's an object, it will added as is to the chain.
-- @treturn PolicyChain New PolicyChain
function _M.build(modules)
    local chain = {}
    local list = modules or { 'apicast.policy.apicast' }

    for i=1, #list do
        -- TODO: make this error better, possibly not crash and just log and skip the module
        local policy, err = _M.load_policy(list[i])

        if policy then
            chain[i] = policy
        else
            error(format('module %q could not be loaded: %s', list[i], err))
        end
    end

    return _M.new(chain)
end


local DEFAULT_POLICIES = {
    'apicast.policy.load_configuration',
    'apicast.policy.find_service',
    'apicast.policy.local_chain',
    'apicast.policy.nginx_metrics'
}

--- Return new policy chain with default policies.
-- @treturn PolicyChain
function _M.default()
    return _M.build(DEFAULT_POLICIES)
end

--- Load a module
-- If the module is a string, returns the result of initializing it with the
-- given arguments. Otherwise, this function simply returns the module
-- received.
-- @tparam string|table module the module or its name
-- @tparam ?table ... params needed to initialize the module
-- @treturn object|nil, nil|string The module instantiated or an error message.
function _M.load_policy(module, version, ...)
    if type(module) == 'string' then
        if sub(module, 1, 14) == 'apicast.policy' then
            module = sub(module, 16)
            version = 'builtin'
        end

        local mod, err = policy_loader:pcall(module, version or 'builtin')

        if mod then
            local new_policy_ok, policy, new_err = pcall(mod.new, ...)
            if new_policy_ok then
                return policy, new_err
            else
                ngx.log(ngx.ERR, 'Policy ', module, ' crashed in .new(). It will be ignored.')
                return nil, policy
            end
        else
            return nil, err
        end
    else
        return module
    end
end

--- Initialize new @{PolicyChain}.
-- @treturn PolicyChain
function _M.new(list)
    local chain = list or {}

    local self = setmetatable(chain, mt)
    chain.config = self:export()
    return self
end

---------------------
--- @type PolicyChain
-- An instance of @{policy_chain}.

--- Export the shared context of the chain
-- @treturn linked_list The context of the chain. Note: the list returned is
--   read-only.
function _M:export()
    local chain = self.config

    if chain then return chain end

    for i=#self, 1, -1 do
        local export = self[i].export or noop
        chain = linked_list.readonly(export(self[i]), chain)
    end

    return chain
end

--- Freeze the policy chain to prevent modifications.
-- After calling this method it won't be possible to insert more policies.
-- @treturn PolicyChain returns self
function _M:freeze()
    self.frozen = true
    return self
end

--- Insert a policy into the chain
-- @tparam Policy policy the policy to be added to the chain
-- @tparam[opt] int position the position to add the policy to, defaults to last one
-- @treturn int length of the chain
-- @error frozen | returned when chain is not modifiable
-- @see freeze
function _M:insert(policy, position)
    if self.frozen then
        return nil, 'frozen'
    else
        insert(self, position or #self+1, policy)
        return #self
    end
end

--- Load and insert policy into the chain
-- @tparam string name policy name
-- @tparam[opt] string version policy version
-- @tparam[opt] table configuration policy configuration
-- @treturn length of the chain
-- @error frozen | returned when chain is not modifiable
-- @see insert
function _M:add_policy(name, version, ...)
    local policy, err = _M.load_policy(name, version, ...)

    if policy then
        return self:insert(policy)

    elseif err then
        ngx.log(ngx.WARN, 'failed to load policy: ', name, ' version: ', version)
        ngx.log(ngx.DEBUG, err)

        return false, err
    end
end

-- Checks if there are any policies placed in the wrong place in the chain.
-- It doesn't return anything, it prints error messages when there's a problem.
function _M:check_order(manifests)
    PolicyOrderChecker.new(
        manifests or policy_manifests_loader.get_all()
    ):check(self)
end

local function call_chain(phase_name)
    return function(self, context)
        for i=1, #self do
            ngx.log(ngx.DEBUG, 'policy chain execute phase: ', phase_name, ', policy: ', self[i]._NAME, ', i: ', i)
            self[i][phase_name](self[i], context)
        end

        return ipairs(self)
    end
end

for _,phase in policy_phases() do
    _M[phase] = call_chain(phase)
end

return _M.build():freeze()
