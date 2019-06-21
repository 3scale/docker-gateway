--- Policy module
-- Policies should define a method for each of the nginx phases (rewrite,
-- access, etc.) in which they want to run code. When Apicast runs each of
-- those phases, if the policy has been loaded, it will run the code in the
-- method with the phase name. So for example, if we want to define a policy
-- that needs to execute something in the rewrite phase, we need to write
-- a 'rewrite' method.

local _M = { }

local REQUEST_PHASES = {
    'rewrite', 'access',
    'content', 'balancer',
    'header_filter', 'body_filter',
    'post_action',  'log', 'metrics',

    'ssl_certificate',
}

local INIT_PHASES = {
    'init', 'init_worker',
}

local PHASES = { }

table.move(INIT_PHASES, 1, #INIT_PHASES, #PHASES + 1, PHASES)
table.move(REQUEST_PHASES, 1, #REQUEST_PHASES, #PHASES + 1, PHASES)

local GC = require('apicast.gc')
local setmetatable_gc_clone = GC.setmetatable_gc_clone
local ipairs = ipairs
local format = string.format

local noop = function() end

local function __tostring(policy)
    return format("Policy: %s (%s)", policy._NAME, policy._VERSION)
end

local function __eq(policy, other)
    return policy._NAME == other._NAME and policy._VERSION == other._VERSION
end

--- Initialize new policy
-- Returns a new policy that you can extend however you want.
-- @tparam string name Name of the new policy.
-- @tparam string version Version of the new policy. Default value is 0.0
-- @treturn policy New policy
-- @treturn table New policy metatable.
function _M.new(name, version)
    local policy = {
        _NAME = name,
        _VERSION = version or '0.0',
    }

    local mt = { __index = policy, __tostring = __tostring, policy = policy }

    function policy.new()
        local p = setmetatable_gc_clone({}, mt)

        return p
    end

    for _, phase in _M.phases() do
        policy[phase] = noop
    end

    return setmetatable(policy, { __tostring = __tostring, __eq = __eq }), mt
end

function _M.phases()
    return ipairs(PHASES)
end

function _M.request_phases()
    return ipairs(REQUEST_PHASES)
end

return _M
