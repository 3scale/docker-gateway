--- Caching policy
-- Configures a cache for the authentication calls against the 3scale backend.
-- The 3scale backend can authorize (status code = 200) and deny (status code =
-- 4xx) calls. When it fails, it returns a 5xx code.
-- This policy support four kinds of caching:
--   - Strict: it only caches authorized calls. Denied and failed calls
--     invalidate the cache entry.
--   - Resilient: caches authorized and denied calls. Failed calls do not
--     invalidate the cache. This allows us to authorize and deny calls
--     according to the result of the last request made even when backend is
--     down.
--   - Allow: caches authorized and denied calls. When backend is unavailable,
--     it will cache an authorization. In practice, this means that when
--     backend is down _any_ request will be authorized unless last call to
--     backend for that request returned 'deny' (status code = 4xx).
--     Make sure to understand the implications of that before using this mode.
--     It makes sense only in very specific use cases.
--   - None: disables caching.

local policy = require('apicast.policy')
local _M = policy.new('Caching policy', 'builtin')

local new = _M.new

local function strict_handler(cache, cached_key, response, ttl)
  if response.status == 200 then
    ngx.log(ngx.INFO, 'apicast cache write key: ', cached_key, ', ttl: ', ttl)
    cache:set(cached_key, 200, ttl or 0)
  else
    ngx.log(ngx.NOTICE, 'apicast cache delete key: ', cached_key,
                        ' cause status ', response.status)
    cache:delete(cached_key)
  end
end

local function resilient_handler(cache, cached_key, response, ttl)
  local status = response.status

  if status and status < 500 then
    ngx.log(ngx.INFO, 'apicast cache write key: ', cached_key,
                      ' status: ', status, ', ttl: ', ttl)

    cache:set(cached_key, status, ttl or 0)
  end
end

local function handle_500_allow_mode(cache, cached_key, ttl)
  -- There is no cas operation in ngx.shared.dict, so getting the value and
  -- then setting it according to it, would generate a race condition.
  -- `add()` works in this case because:
  -- If there's already a 2XX, we do not need to write anything.
  -- If there's a 4XX, we do not need to overwrite it.
  -- Else, there's a nil and we need to write a 200.
  cache:add(cached_key, 200, ttl)
end

local function allow_handler(cache, cached_key, response, ttl)
  local status = response.status

  if status and status < 500 then
    ngx.log(ngx.INFO, 'apicast cache write key: ', cached_key,
                      ' status: ', status, ', ttl: ', ttl)

    cache:set(cached_key, status, ttl or 0)
  else
    handle_500_allow_mode(cache, cached_key, ttl or 0)
  end
end

local function disabled_cache_handler()
  ngx.log(ngx.DEBUG, 'Caching is disabled. Skipping cache handler.')
end

local handlers = {
  resilient = resilient_handler,
  strict = strict_handler,
  allow = allow_handler,
  none = disabled_cache_handler
}

local function handler(config)
  if not config.caching_type then
    ngx.log(ngx.ERR, 'Caching type not specified. Disabling cache.')
    return handlers.none
  end

  local res = handlers[config.caching_type]

  if not res then
    ngx.log(ngx.ERR, 'Invalid caching type. Disabling cache.')
    res = handlers.none
  end

  return res
end

--- Initialize a Caching policy.
-- @tparam[opt] table config
-- @field caching_type Caching type (strict, resilient, allow, none)
function _M.new(config)
  local self = new(config)
  self.cache_handler = handler(config or {})
  return self
end

function _M:export()
  return { cache_handler = self.cache_handler }
end

return _M
