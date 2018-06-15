--- Executor module
-- The executor has a policy chain and will simply forward the calls it
-- receives to that policy chain. It also manages the 'context' that is passed
-- when calling the policy chain methods. This 'context' contains information
-- shared among policies.

require('apicast.loader') -- to load code from deprecated paths

local PolicyChain = require('apicast.policy_chain')
local policy = require('apicast.policy')
local linked_list = require('apicast.linked_list')
local prometheus = require('apicast.prometheus')
local policy_loader = require('apicast.policy_loader')

local setmetatable = setmetatable
local ipairs = ipairs

local _M = { }

local mt = { __index = _M }

local policy_modules = policy_loader:get_all()

-- forward all policy methods to the policy chain
for _,phase in policy.phases() do
    _M[phase] = function(self, ...)
        ngx.log(ngx.DEBUG, 'executor phase: ', phase)
        return self.policy_chain[phase](self.policy_chain, self:context(phase), ...)
    end
end

function _M.new(policy_chain)
    return setmetatable({ policy_chain = policy_chain:freeze() }, mt)
end

local function build_context(executor)
    local config = executor.policy_chain:export()

    return linked_list.readwrite({}, config)
end

local function shared_build_context(executor)
    local ctx = ngx.ctx or {}
    local context = ctx.context

    if not context then
        context = build_context(executor)

        ctx.context = context
    end

    return context
end

--- Shared context among policies
-- @tparam string phase Nginx phase
-- @treturn linked_list The context. Note: The list returned is 'read-write'.
function _M:context(phase)
    if phase == 'init' then
        return build_context(self)
    end

    return shared_build_context(self)
end

local init = _M.init
function _M:init()
    init(self)

    for _, policy_mod in ipairs(policy_modules) do
       if policy_mod.init then
           policy_mod.init()
       end
    end
end

local init_worker = _M.init_worker
function _M:init_worker()
    init_worker(self)

    for _, policy_mod in ipairs(policy_modules) do
        if policy_mod.init_worker then
            policy_mod.init_worker()
        end
    end
end

local metrics = _M.metrics
--- Render metrics from all policies.
function _M:metrics(...)
    metrics(self, ...)
    return prometheus:collect()
end

return _M.new(PolicyChain.default())
