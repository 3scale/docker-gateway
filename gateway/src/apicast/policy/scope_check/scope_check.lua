local policy = require('apicast.policy')
local _M = policy.new('Scope Check Policy')

local ipairs = ipairs
local MappingRule = require('apicast.mapping_rule')

local new = _M.new

local function init_mapping_rules(scopes)
  for _, scope in ipairs(scopes) do
    scope.mapping_rule = MappingRule.from_proxy_rule({
      http_method = 'GET',
      pattern = scope.resource,
      querystring_parameters = {},
      metric_system_name = 'hits',
      delta = 1
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
  local matched_each_role = false
  for _, role_in_token in ipairs(roles_in_token) do
    if role == role_in_token then
      matched_each_role = true
      break
    end
  end

  return matched_each_role
end

local function scope_check(scopes, jwt)
  local uri = ngx.var.uri

  for _, scope in ipairs(scopes) do
    -- resource check
    if scope.mapping_rule:matches('GET', uri) then
      -- role check
      local matched_all_role = true

      if scope.client_roles then
        for _, role in ipairs(scope.client_roles) do
          if not jwt.resource_access or not jwt.resource_access[role.client] then
            matched_all_role = false
            break
          end

          if not check_roles_in_token(role.name, jwt.resource_access[role.client].roles) then
            matched_all_role = false
            break
          end
        end
      end

      if scope.realm_roles then
        for _, role in ipairs(scope.realm_roles) do
          if not jwt.realm_access then
            matched_all_role = false
            break
          end

          if not check_roles_in_token(role.name, jwt.realm_access.roles) then
            matched_all_role = false
            break
          end
        end
      end

      if matched_all_role then return true end
    end
  end

  return false
end

function _M:access(context)
  if scope_check(self.scopes, context.jwt) then
    if self.type == "blacklist" then
      ngx.status = context.service.auth_failed_status
      ngx.say(context.service.error_auth_failed)
      return ngx.exit(ngx.status)
    end
  else
    if self.type == "whitelist" then
      ngx.status = context.service.auth_failed_status
      ngx.say(context.service.error_auth_failed)
      return ngx.exit(ngx.status)
    end
  end
  return true
end

return _M
