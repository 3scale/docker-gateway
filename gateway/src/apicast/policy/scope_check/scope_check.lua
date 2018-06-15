local policy = require('apicast.policy')
local _M = policy.new('Scope Check Policy')

local ngx_variable = require ('apicast.policy.ngx_variable')

local ipairs = ipairs
local format = string.format
local gsub = ngx.re.gsub
local match = ngx.re.match

local TemplateString = require 'apicast.template_string'

local new = _M.new

local function build_templates(scopes)
  scopes.template_string = TemplateString.new(
    "{{uri}}", "liquid")

  for _, scope in ipairs(scopes) do
    for _, role in ipairs(scope.roles) do
      if role.client then
        local value = format(
          "{%%for k in jwt.resource_access.%s.roles%%} {{k}} {%% endfor%%}", role.client)
        role.template_string = TemplateString.new(
          value, "liquid", 50000)
      else
        role.template_string = TemplateString.new(
          "{%for k in jwt.realm_access.roles%} {{k}} {% endfor%}", "liquid", 50000)
      end
    end
  end
end

function _M.new(config)
  local self = new()
  self.config = config or {}
  self.type = config.type or "whitelist"
  self.scopes = config.scopes or {}

  build_templates(self.scopes)

  return self
end

local function scope_check(self, context)
  local uri = self.scopes.template_string:render(ngx_variable.available_context(context))

  for _, scope in ipairs(self.scopes) do
    local uri_regex, _, _ = gsub(scope.resource, "\\*", ".*")
    uri_regex = format("^%s$", uri_regex)

    local m_uri, _ = match(uri, uri_regex)
    if m_uri then
      -- role check
      local matched = true
      for _, role in ipairs(scope.roles) do
        local roles_in_token = role.template_string:render(context)
        local m_role, _ = match(roles_in_token, role.role)
        if not m_role then
          matched = false
          break
        end
      end
      if matched then return { match = true } end
    end
  end

  return { match = false }
end

function _M:access(context)
  if scope_check(self, context).match == true then
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
