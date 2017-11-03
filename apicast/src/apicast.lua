local proxy = require('proxy')
local balancer = require('balancer')
local math = math
local setmetatable = setmetatable

local configuration_loader = require('configuration_loader').new()
local configuration_store = require('configuration_store')
local user_agent = require('user_agent')
local env = require 'resty.env'

local url_rewriting = env.enabled('APICAST_URL_REWRITING')

local noop = function() end

local _M = {
  _VERSION = '3.0.0-pre',
  _NAME = 'APIcast'
}

local mt = {
  __index = _M
}

--- This is called when APIcast boots the master process.
function _M.new()
  return setmetatable({
    configuration = configuration_store.new(),
    -- So there is no way to use ngx.ctx between request and post_action.
    -- We somehow need to share the instance of the proxy between those.
    -- This table is used to store the proxy object with unique reqeust id key
    -- and removed in the post_action. Because it there is just one instance
    -- of this module in each worker.
    post_action_proxy = {}
  }, mt)
end

function _M:init()
  user_agent.cache()

  math.randomseed(ngx.now())
  -- First calls to math.random after a randomseed tend to be similar; discard them
  for _=1,3 do math.random() end

  configuration_loader.init(self.configuration)
end

function _M:init_worker()
  configuration_loader.init_worker(self.configuration)
end

function _M.cleanup()
  -- now abort all the "light threads" running in the current request handler
  ngx.exit(499)
end

function _M:rewrite()
  ngx.on_abort(_M.cleanup)

  ngx.var.original_request_id = ngx.var.request_id

  local host = ngx.var.host
  -- load configuration if not configured
  -- that is useful when lua_code_cache is off
  -- because the module is reloaded and has to be configured again

  local configuration = configuration_loader.rewrite(self.configuration, host)

  local p = proxy.new(configuration)
  local service = p:set_service(host)
  if not url_rewriting then
    p.set_upstream(service)
  end
  ngx.ctx.proxy = p
end

function _M:post_action()
  local request_id = ngx.var.original_request_id
  local post_action_proxy = self.post_action_proxy

  if not post_action_proxy then
    return nil, 'not initialized'
  end

  local p = ngx.ctx.proxy or post_action_proxy[request_id]

  post_action_proxy[request_id] = nil

  if p then
    return p:post_action()
  else
    ngx.log(ngx.INFO, 'could not find proxy for request id: ', request_id)
    return nil, 'no proxy for request'
  end
end

function _M:access()
  local p = ngx.ctx.proxy
  local post_action_proxy = self.post_action_proxy

  if not post_action_proxy then
    return nil, 'not initialized'
  end

  local access, handler = p:call() -- proxy:access() or oauth handler

  local ok, err

  if access then
    ok, err = access()
    post_action_proxy[ngx.var.original_request_id] = p
  elseif handler then
    ok, err = handler()
    -- no proxy because that would trigger post action
  end

  return ok, err
end

_M.body_filter = noop
_M.header_filter = noop

_M.balancer = balancer.call

_M.log = noop

return _M
