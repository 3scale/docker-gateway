--- Policy loader
-- This module loads a policy defined by its name and version.
-- It uses sandboxed require to isolate dependencies and not mutate global state.
-- That allows for loading several versions of the same policy with different dependencies.
-- And even loading several independent copies of the same policy with no shared state.
-- Each object returned by the loader is new table and shares only shared APIcast code.

local sandbox = require('resty.sandbox')
local cjson = require('cjson')

local format = string.format
local ipairs = ipairs
local insert = table.insert
local concat = table.concat
local setmetatable = setmetatable
local pcall = pcall

local _M = {}

local resty_env = require('resty.env')
local re = require('ngx.re')

do
  local function apicast_dir()
    return resty_env.value('APICAST_DIR') or '.'
  end

  local function policy_load_path()
    return resty_env.value('APICAST_POLICY_LOAD_PATH') or
      format('%s/policies', apicast_dir())
  end

  function _M.policy_load_paths()
    return re.split(policy_load_path(), ':', 'oj')
  end

  function _M.builtin_policy_load_path()
    return resty_env.value('APICAST_BUILTIN_POLICY_LOAD_PATH') or format('%s/src/apicast/policy', apicast_dir())
  end
end

-- Returns true if config validation has been enabled via ENV or if we are
-- running Test::Nginx integration tests. We know that the framework always
-- sets TEST_NGINX_BINARY so we can use it to detect whether we are running the
-- tests.
local function policy_config_validation_is_enabled()
  return resty_env.enabled('APICAST_VALIDATE_POLICY_CONFIGS')
    or resty_env.value('TEST_NGINX_BINARY')
end

local policy_config_validator = { validate_config = function() return true end }
if policy_config_validation_is_enabled() then
  policy_config_validator = require('apicast.policy_config_validator')
end

local function read_manifest(path)
  local handle = io.open(format('%s/%s', path, 'apicast-policy.json'))

  if handle then
    local contents = handle:read('*a')

    handle:close()

    return cjson.decode(contents)
  end
end

local function lua_load_path(load_path)
  return format('%s/?.lua', load_path)
end

local function load_manifest(name, version, path)
  local manifest = read_manifest(path)

  if manifest then
      if manifest.version ~= version then
        ngx.log(ngx.ERR, 'Not loading policy: ', name,
          ' path: ', path,
          ' version: ', version, '~= ', manifest.version)
        return
      end

    return manifest, lua_load_path(path)
  end

  return nil, lua_load_path(path)
end

local function with_config_validator(policy, policy_config_schema)
  local original_new = policy.new

  local new_with_validator = function(config)
    local is_valid, err = policy_config_validator.validate_config(
      config, policy_config_schema)

    if not is_valid then
      error(format('Invalid config for policy: %s', err))
    end

    return original_new(config)
  end

  return setmetatable(
    { new = new_with_validator },
    { __index = policy }
  )
end

function _M:load_path(name, version, paths)
  local failures = {}

  for _, path in ipairs(paths or self.policy_load_paths()) do
    local manifest, load_path = load_manifest(name, version, format('%s/%s/%s', path, name, version) )

    if manifest then
      return load_path, manifest.configuration
    else
      insert(failures, load_path)
    end
  end

  if version == 'builtin' then
    local manifest, load_path = load_manifest(name, version, format('%s/%s', self.builtin_policy_load_path(), name) )

    if manifest then
      return load_path, manifest.configuration
    else
      insert(failures, load_path)
    end
  end

  return nil, nil, failures
end

local package_cache = setmetatable({}, {
  __index = function(t, k) local n = { }; t[k] = n; return n end
})

function _M:call(name, version, dir)
  local v = version or 'builtin'
  local load_path, policy_config_schema, invalid_paths = self:load_path(name, v, dir)

  local cache_key = concat({name, v, dir and concat(dir, ',') or '' }, '-')

  local cache = package_cache[cache_key]
  local loader = sandbox.new(load_path and { load_path } or invalid_paths,
          cache)

  ngx.log(ngx.DEBUG, 'loading policy: ', name, ' version: ', v)

  -- passing the "exclusive" flag for the require so it does not fallback to native require
  -- it should load only policies and not other code and fail if there is no such policy
  local res = loader('init', true)

  if policy_config_validation_is_enabled() then
    return with_config_validator(res, policy_config_schema)
  else
    return res
  end
end

function _M:pcall(name, version, dir)
  local ok, ret = pcall(self.call, self, name, version, dir)

  if ok then
    return ret
  else
    return nil, ret
  end
end

return setmetatable(_M, { __call = _M.call })
