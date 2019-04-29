local resty_env = require('resty.env')

local policy = require('apicast.policy')
local Proxy = require('apicast.proxy')
local LinkedList = require('apicast.linked_list')
local _M = policy.new('Local Policy Chain')

local function build_default_chain()
  local module

  if resty_env.value('APICAST_MODULE') then
    -- Needed to keep compatibility with the old module system.
    module = assert(require('apicast.module'), 'could not load custom module')
  else
    module = 'apicast.policy.apicast'
  end

  return require('apicast.policy_chain').build({ module })
end

local default_chain = build_default_chain()

local function find_policy_chain(context)
  return context.policy_chain or (context.service and context.service.policy_chain) or default_chain
end

local function build_chain(context)
  local proxy = Proxy.new(context.configuration)

  context.proxy = context.proxy or proxy

  local policy_chain = find_policy_chain(context)
  context.policy_chain = policy_chain

  return policy_chain
end

-- forward all policy methods to the policy chain
for _, phase in policy.phases() do
  _M[phase] = function(_, context, ...)
    local policy_chain = find_policy_chain(context)

    if policy_chain then
      local merged_context = LinkedList.readwrite(context, policy_chain:export())
      return policy_chain[phase](policy_chain, merged_context, ...)
    end
  end
end

local rewrite = _M.rewrite

-- Similar to the methods defined just above. The only difference is that this
-- one builds the policy chain.
function _M:rewrite(context, ...)
  local policy_chain = build_chain(context)

  local merged_context = LinkedList.readwrite(context, policy_chain:export())

  rewrite(self, merged_context, ...)
end

return _M
