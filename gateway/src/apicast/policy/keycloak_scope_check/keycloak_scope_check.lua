--- Keycloak Scope Check Policy
-- This policy verifies the realm roles and the client roles in the JWT.
--
--- The realm roles are specified when you want to add scope check to the every client's resources or 3scale itself.
-- https://www.keycloak.org/docs/4.0/server_admin/index.html#realm-roles
--
-- When you specify the realm roles in Keycloak, the JWT includes them as follows:
--
-- {
--   "realm_access": {
--     "roles": [
--       "<realm_role_A>", "<realm_role_B>"
--     ]
--   }
-- }
--
-- And you need to specify the "realm_roles" in this policy as follows:
--
-- "realm_roles": [
--   { "name": "<realm_role_A>" }, { "name": "<realm_role_B>" }
-- ]
--
--- The client roles are specified when you want to add scope check to the particular client's resources.
-- https://www.keycloak.org/docs/4.0/server_admin/index.html#client-roles
--
-- When you specify the client roles in Keycloak, the JWT includes them as follows:
--
-- {
--   "resource_access": {
--     "<client_A>": {
--       "roles": [
--         "<client_role_A>", "<client_role_B>"
--       ]
--     },
--     "<client_B>": {
--       "roles": [
--         "<client_role_A>", "<client_role_B>"
--       ]
--     }
--   }
-- }
--
-- And you need to specify the "client_roles" in this policy as follows:
--
-- "client_roles": [
--   { "name": "<client_role_A>", "client": "<client_A>" },
--   { "name": "<client_role_B>", "client": "<client_A>" },
--   { "name": "<client_role_A>", "client": "<client_B>" },
--   { "name": "<client_role_B>", "client": "<client_B>" }
-- ]

local policy = require('apicast.policy')
local _M = policy.new('Keycloak Scope Check Policy')

local ipairs = ipairs
local MappingRule = require('apicast.mapping_rule')

local new = _M.new

local function init_mapping_rules(scopes)
  for _, scope in ipairs(scopes) do
    scope.mapping_rule = MappingRule.from_proxy_rule({
      http_method = 'ANY',
      pattern = scope.resource,
      querystring_parameters = {},
      metric_system_name = 'hits'
    })
  end
end

function _M.new(config)
  local self = new()
  self.config = config or {}
  self.type = config.type or "whitelist"
  self.scopes = config.scopes or {}

  init_mapping_rules(self.scopes)

  return self
end

local function check_roles_in_token(role, roles_in_token)
  for _, role_in_token in ipairs(roles_in_token) do
    if role == role_in_token then return true end
  end

  return false
end

local function match_realm_roles(scope, jwt)
  if not scope.realm_roles then return true end

  for _, role in ipairs(scope.realm_roles) do
    if not jwt.realm_access then
      return false
    end

    if not check_roles_in_token(role.name, jwt.realm_access.roles) then
      return false
    end
  end

  return true
end

local function match_client_roles(scope, jwt)
  if not scope.client_roles then return true end

  for _, role in ipairs(scope.client_roles) do
    if not jwt.resource_access then
      return false
    end

    local client = jwt.resource_access[role.client]

    if not client then
      return false
    end

    if not check_roles_in_token(role.name, client.roles) then
      return false
    end
  end

  return true
end

local function scope_check(scopes, jwt)
  local uri = ngx.var.uri

  for _, scope in ipairs(scopes) do

    if scope.mapping_rule:matches('ANY', uri) then
      if match_realm_roles(scope, jwt) and match_client_roles(scope, jwt) then
        return true
      end
    end

  end

  return false
end

local function auth_failed(service)
  ngx.status = service.auth_failed_status
  ngx.say(service.error_auth_failed)
  return ngx.exit(ngx.status)
end

function _M:access(context)
  if scope_check(self.scopes, context.jwt) then
    if self.type == "blacklist" then
      auth_failed(context.service)
    end
  else
    if self.type == "whitelist" then
      auth_failed(context.service)
    end
  end
  return true
end

return _M
