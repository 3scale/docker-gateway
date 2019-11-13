--- Default credentials policy

local tostring = tostring

local policy = require('apicast.policy')
local _M = policy.new('Default credentials policy', 'builtin')

local new = _M.new

function _M.new(config)
  local self = new(config)

  if config then
    self.default_credentials = {
      user_key = config.user_key,
      app_id = config.app_id,
      app_key = config.app_key
    }
  else
    self.default_credentials = {}
  end

  return self
end

local function creds_missing(service)
  local service_creds = service:extract_credentials()
  if not service_creds then return true end

  local backend_version = tostring(service.backend_version)

  if backend_version == '1' then
    return service_creds.user_key == nil
  elseif backend_version == '2' then
    return service_creds.app_id == nil and service_creds.app_key == nil
  end
end

local function provide_creds_for_version_1(context, default_creds)
  if default_creds.user_key then
    -- follows same format as Service.extract_credentials()
    context.extracted_credentials = {
      default_creds.user_key,
      user_key = default_creds.user_key
    }

    ngx.log(ngx.DEBUG, 'Provided default creds for request')
  else
    ngx.log(ngx.WARN, 'No default user key configured')
  end
end

local function provide_creds_for_version_2(context, default_creds)
  if default_creds.app_id and default_creds.app_key then
    -- follows same format as Service.extract_credentials()
    context.extracted_credentials = {
      default_creds.app_id,
      default_creds.app_key,
      app_id = default_creds.app_id,
      app_key = default_creds.app_key
    }

    ngx.log(ngx.DEBUG, 'Provided default creds for request')
  else
    ngx.log(ngx.WARN, 'No default app_id + app_key configured')
  end
end

local creds_provider = {
  ["1"] = provide_creds_for_version_1,
  ["2"] = provide_creds_for_version_2
}

local function backend_version_is_supported(backend_version)
  return creds_provider[backend_version] ~= nil
end

local function provide_creds(context, backend_version, default_creds)
  creds_provider[tostring(backend_version)](context, default_creds)
end

function _M:rewrite(context)
  local service = context.service

  if not service then
    ngx.log(ngx.ERR, 'No service in the context')
    return
  end

  local backend_version = tostring(service.backend_version)
  if not backend_version_is_supported(backend_version) then
    ngx.log(ngx.ERR, 'Incompatible backend version: ', backend_version)
    return
  end

  if creds_missing(service) then
    provide_creds(context, service.backend_version, self.default_credentials)
  end
end

return _M
