local policy = require('apicast.policy')
local _M = policy.new('Decode the OpenID Connect token and make it available in the context')

local jwt = require("resty.jwt")

function _M:access(context, host)
  local credentials, err = ngx.ctx.service:extract_credentials()
  local access_token = credentials.access_token

  -- Decode the JWT token but we do NOT validate it since it has already
  -- been done by the 'apicast.policy.apicast' policy before.
  local jwt_obj = jwt:load_jwt(access_token)
  if not jwt_obj.valid then
    ngx.log(ngx.WARN, "Could not decode JWT: ", jwt_obj.reason)
    return
  end

  local payload = jwt_obj.payload
  context.jwt = payload
end

return _M
