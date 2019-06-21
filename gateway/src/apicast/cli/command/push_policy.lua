local setmetatable = setmetatable

local policy_pusher = require('apicast.policy_pusher').new()

local _M = { }

local mt = { __index = _M }

function mt.__call(_, opts)
  policy_pusher:push(
    opts.name, opts.version, opts.admin_portal_domain, opts.access_token
  )
end

local function configure(cmd)
  cmd:argument('name', 'the name of the policy')
  cmd:argument('version', 'the version of the policy')
  cmd:argument('admin_portal_domain', 'your admin portal domain. If you are using SaaS it is YOUR_ACCOUNT-admin.3scale.net')
  cmd:argument('access_token', 'an access token that you can get from the 3scale admin portal')
  return cmd
end

function _M.new(parser)
  local cmd = configure(
    parser:command('push_policy', 'Push a policy manifest to the 3scale admin portal')
  )

  return setmetatable({ parser = parser, cmd = cmd }, mt)
end

return setmetatable(_M, mt)
