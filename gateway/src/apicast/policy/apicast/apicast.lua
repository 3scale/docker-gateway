local balancer = require('apicast.balancer')
local errors = require('apicast.errors')

local math = math
local setmetatable = setmetatable
local assert = assert

local user_agent = require('apicast.user_agent')

local _M = require('apicast.policy').new('APIcast', 'builtin')

local mt = {
  __index = _M
}

--- This is called when APIcast boots the master process.
function _M.new()
  return setmetatable({
  }, mt)
end

function _M.init()
  user_agent.cache()

  math.randomseed(ngx.now())
  -- First calls to math.random after a randomseed tend to be similar; discard them
  for _=1,3 do math.random() end
end

function _M.cleanup()
  -- now abort all the "light threads" running in the current request handler
  ngx.exit(499)
end

function _M:rewrite(context)
  ngx.on_abort(self.cleanup)

  -- load configuration if not configured
  -- that is useful when lua_code_cache is off
  -- because the module is reloaded and has to be configured again

  local p = context.proxy

  if not p then
    return nil, 'no proxy object'
  end

  if context.cache_handler then
    p.cache_handler = context.cache_handler
  end

  local service = context.service

  if service then
    ngx.ctx.service = service

    -- it is possible that proxy:rewrite will terminate the request
    p:rewrite(service, context)
  end

  local err
  context[self] = context[self] or {}
  context[self].upstream, err = p.get_upstream(service, context)
  context.get_upstream = function()
    return context[self].upstream
  end

  if err then
    ngx.log(ngx.WARN, "upstream api for the service:", service.id, " is invalid, error:", err)
  end

  ngx.ctx.proxy = p
end

function _M:post_action(context)
  if not (context[self] and context[self].run_post_action) then return end

  local p = context and context.proxy or ngx.ctx.proxy or self.proxy

  if p then
    return p:post_action(context)
  else
    ngx.log(ngx.ERR, 'could not find proxy for request')
    return nil, 'no proxy for request'
  end
end

function _M:access(context)
  if context.skip_apicast_access then return end

  -- Flag to run post_action() only when access() was executed.
  -- Other policies can call ngx.exit(4xx) on access() or rewrite. If they're
  -- placed before APIcast in the chain, the request will be denied and this
  -- access() phase will no be run. However, ngx.exit(4xx) skips some phases,
  -- but not post_action. Post_action would run if we did not set this flag,
  -- and we want to avoid that. Otherwise, post_action could call authrep()
  -- even when another policy denied the request.
  context[self] = context[self] or {}
  context[self].run_post_action = true

  local ctx = ngx.ctx
  local p = context and context.proxy or ctx.proxy or self.proxy

  if p then
    return p:access(context.service, context.usage, context.credentials, context.ttl)
  end
end

function _M:content(context)
  if not context[self].upstream then
    ngx.log(ngx.WARN, "Upstream server not found for this request")
    return errors.upstream_not_found(context.service)
  end

  local upstream = assert(context[self].upstream, 'missing upstream')

  if upstream then
    upstream:call(context)
  end
end

_M.balancer = balancer.call

return _M
