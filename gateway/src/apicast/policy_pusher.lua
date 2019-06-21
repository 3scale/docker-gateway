local policy_manifests_loader = require('apicast.policy_manifests_loader')
local http_ng = require('resty.http_ng')
local resty_env = require('resty.env')

local setmetatable = setmetatable
local format = string.format

local _M = {}

local mt = { __index = _M }

function _M.new(http_client, manifests_loader)
  local self = setmetatable({}, mt)
  self.http_client = http_client or http_ng.new()
  self.policy_manifests_loader = manifests_loader or policy_manifests_loader
  return self
end

local system_endpoint = '/admin/api/registry/policies'

local function system_url(admin_portal_domain)
  return format('https://%s%s', admin_portal_domain, system_endpoint)
end

local function push_to_system(name, version, manifest, admin_portal_domain, access_token, http_client)
  local url = system_url(admin_portal_domain)

  return http_client.json.post(
    url,
    { access_token = access_token, name = name, version = version, schema = manifest },
    { ssl = { verify = resty_env.enabled('OPENSSL_VERIFY') } }
  )
end

local function show_msg(http_resp, err)
  if http_resp then
    if http_resp.status >= 200 and http_resp.status < 300 then
      ngx.log(ngx.INFO, 'Pushed the policy')
    else
      ngx.log(ngx.ERR, 'Error while pushing the policy: ', http_resp.body)
    end
  else
    ngx.log(ngx.ERR, 'Could not push the policy to 3scale: ', err)
  end
end

function _M:push(name, version, admin_portal_domain, access_token)
  local policy_manifest = self.policy_manifests_loader.get(name, version)
  if policy_manifest then
    local res, err = push_to_system(
      name, version, policy_manifest, admin_portal_domain, access_token, self.http_client
    )

    show_msg(res, err)
  else
    ngx.log(ngx.ERR, 'Cannot find policy with name: ', name, ' and version: ', version)
  end
end

return _M
