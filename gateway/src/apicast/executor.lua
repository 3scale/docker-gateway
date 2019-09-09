--- Executor module
-- The executor has a policy chain and will simply forward the calls it
-- receives to that policy chain. It also manages the 'context' that is passed
-- when calling the policy chain methods. This 'context' contains information
-- shared among policies.

require('apicast.loader') -- to load code from deprecated paths

local PolicyChain = require('apicast.policy_chain')
local Policy = require('apicast.policy')
local linked_list = require('apicast.linked_list')
local prometheus = require('apicast.prometheus')
local uuid = require('resty.jit-uuid')

local setmetatable = setmetatable
local ipairs = ipairs

local _M = { }

local mt = { __index = _M }

-- forward all policy methods to the policy chain
for _,phase in Policy.phases() do
    _M[phase] = function(self)
        ngx.log(ngx.DEBUG, 'executor phase: ', phase)
        return self.policy_chain[phase](self.policy_chain, self:context(phase))
    end
end

function _M.new(policy_chain)
    return setmetatable({ policy_chain = policy_chain:freeze() }, mt)
end

local function build_context(executor)
    local config = executor.policy_chain:export()

    return linked_list.readwrite({}, config)
end

local function store_original_request(context)
  -- There are a few phases[0] that req and var are not set and API is
  -- disabled. The reason to call this using a pcall function is to avoid to
  -- define the phases manually that are error prone. Also in openresty there
  -- is not a good method to check this. [1]
  -- [0] invalid phases: init_worker, init, timer and ssl_cer
  -- [1] https://github.com/openresty/lua-resty-core/blob/9937f5d83367e388da4fcc1d7de2141c9e38d7e2/lib/resty/core/request.lua#L96
  --
  if not context or context.original_request then
    return
  end

  pcall(function()
    context.original_request = linked_list.readonly({
      headers = ngx.req.get_headers(),
      host = ngx.var.host,
      path = ngx.var.request_uri,
      uri = ngx.var.uri,
      server_addr = ngx.var.server_addr,
    })
  end)
end

local function shared_build_context(executor)
    local ok, ctx = pcall(function() return ngx.ctx end)
    if not ok then
      ctx = {}
    end

    local context = ctx.context

    if not context then
        context = build_context(executor)
        ctx.context = context
    end

    if not ctx.original_request then
        store_original_request(ctx)
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

do
    local policy_loader = require('apicast.policy_loader')
    local policies

    local init = _M.init
    function _M:init()
        local executed = {}

        for _,policy in init(self) do
            executed[policy.init] = true
        end

        policies = policy_loader:get_all()

        for _, policy in ipairs(policies) do
            if not executed[policy.init] then
                policy.init()
                executed[policy.init] = true
            end
        end
    end

    local init_worker = _M.init_worker
    function _M:init_worker()
        -- Need to seed the UUID in init_worker.
        -- Ref: https://github.com/thibaultcha/lua-resty-jit-uuid/blob/c4c0004da0c4c4cdd23644a5472ea5c0d18decbb/README.md#usage
        uuid.seed()

        local executed = {}

        for _,policy in init_worker(self) do
            executed[policy.init_worker] = true
        end

        for _, policy in ipairs(policies or policy_loader:get_all()) do
            if not executed[policy.init_worker] then
                policy.init_worker()
                executed[policy.init_worker] = true
            end
        end
    end

    -- balancer() cannot be forwarded directly because we want to keep track of
    -- the number of times the balancer phase was executed for the current
    -- request. That's needed for retrying the upstream request a given number
    -- of times.
    -- Having this counter in the retry policy instead of here would impose
    -- restrictions on the place the retry policy needs to occupy in the chain.
    -- The counter is used in the balancer module, which can be called from
    -- several policies. The counter would only be updated if the retry policy
    -- was run because the others than run on balancer().
    function _M:balancer()
        local context = self:context('balancer')
        context.balancer_retries = (context.balancer_retries and context.balancer_retries + 1) or 0
        context.peer_set_in_current_balancer_try = false
        return self.policy_chain.balancer(self.policy_chain, context)
    end

    function _M.reset_available_policies()
        policies = policy_loader:get_all()
    end
end

local metrics = _M.metrics
--- Render metrics from all policies.
function _M:metrics(...)
    metrics(self, ...)
    return prometheus:collect()
end

return _M.new(PolicyChain.default())
