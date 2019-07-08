--- Keycloak Role Check Policy
-- This policy verifies the realm roles and the client roles in the JWT.
--
--- The realm roles are specified when you want to add role check to the every client's resources or 3scale itself.
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
--- The client roles are specified when you want to add role check to the particular client's resources.
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
local _M = policy.new('Keycloak Role Check Policy', 'builtin')

local ipairs = ipairs
local MappingRule = require('apicast.mapping_rule')
local TemplateString = require('apicast.template_string')
local errors = require('apicast.errors')
local default_type = 'plain'

local new = _M.new

local any_method = MappingRule.any_method

local function create_template(value, value_type)
  return TemplateString.new(value, value_type or default_type)
end

local function build_scopes(scopes)
  for _, scope in ipairs(scopes) do

    if scope.realm_roles then
      for _, realm_role in ipairs(scope.realm_roles) do
        realm_role.template_string = create_template(
          realm_role.name, realm_role.name_type)
      end
    end

    if scope.client_roles then
      for _, client_role in ipairs(scope.client_roles) do
        client_role.name_template_string = create_template(
          client_role.name, client_role.name_type)

        client_role.client_template_string = create_template(
          client_role.client, client_role.client_type)
      end
    end

    scope.resource_template_string = create_template(
      scope.resource, scope.resource_type)
    if (not scope.methods) or (scope.methods and #scope.methods == 0 ) then
      scope.methods = { any_method }
    end

  end

end

function _M.new(config)
  local self = new()
  self.type = config.type or "whitelist"
  self.scopes = config.scopes or {}

  build_scopes(self.scopes)

  return self
end

local function check_roles_in_token(role, roles_in_token)
  for _, role_in_token in ipairs(roles_in_token) do
    if role == role_in_token then return true end
  end

  return false
end

local function match_realm_roles(scope, context)
  if not scope.realm_roles then return true end

  for _, role in ipairs(scope.realm_roles) do
    if not context.jwt.realm_access then
      return false
    end

    local name = role.template_string:render(context)

    if not check_roles_in_token(name, context.jwt.realm_access.roles or {}) then
      return false
    end
  end

  return true
end

local function match_client_roles(scope, context)
  if not scope.client_roles then return true end

  for _, role in ipairs(scope.client_roles) do
    if not context.jwt.resource_access then
      return false
    end

    local client = role.client_template_string:render(context)
    local client_in_token = context.jwt.resource_access[client]

    if not client_in_token then
      ngx.log(ngx.DEBUG, "Client '", client, "' was not found in the access token.")
      return false
    end

    local name = role.name_template_string:render(context)

    if not check_roles_in_token(name, client_in_token.roles or {}) then
      return false
    end
  end

  return true
end

local function validate_scope_access(scope, context, uri, request_method)
  for _, method  in ipairs(scope.methods) do

    local resource = scope.resource_template_string:render(context)

    local mapping_rule = MappingRule.from_proxy_rule({
      http_method = method,
      pattern = resource,
      querystring_parameters = {},
      -- the name of the metric is irrelevant
      metric_system_name = 'hits'
    })

    if mapping_rule:matches(request_method, uri) then
      if match_realm_roles(scope, context) and match_client_roles(scope, context) then
        return true
      end
    end
  end
  return false
end

local function scopes_check(scopes, context)
  local uri = ngx.var.uri
  local request_method =  ngx.req.get_method()

  if not context.jwt then
    return false
  end

  for _, scope in ipairs(scopes) do
    if validate_scope_access(scope, context, uri, request_method) then
      return true
    end
  end

  return false
end

function _M:access(context)
  if scopes_check(self.scopes, context) then
    if self.type == "blacklist" then
      return errors.authorization_failed(context.service)
    end
  else
    if self.type == "whitelist" then
      return errors.authorization_failed(context.service)
    end
  end
  return true
end

return _M
