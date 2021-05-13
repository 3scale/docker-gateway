local _M = {}

local cjson = require('cjson')
local executor = require('apicast.executor')
local router = require('router')
local configuration_parser = require('apicast.configuration_parser')
local configuration_loader = require('apicast.configuration_loader')
local inspect = require('inspect')
local resolver_cache = require('resty.resolver.cache')
local env = require('resty.env')
local policy_manifests_loader = require('apicast.policy_manifests_loader')

local policy_loader = require('apicast.policy_loader')

local live = { status = 'live', success = true }

local function json_response(body, status)
  ngx.header.content_type = 'application/json; charset=utf-8'
  ngx.status = status or ngx.HTTP_OK
  ngx.say(cjson.encode(body))
end

function _M.ready()
  local status = _M.status()
  local code = status.success and ngx.HTTP_OK or 412
  json_response(status, code)
end

function _M.live()
  json_response(live, ngx.HTTP_OK)
end

local function context_configuration()
    return executor:context().configuration or policy_loader:pcall("load_configuration", version or 'builtin')
end

function _M.status(config)
  local configuration = config or context_configuration()
  -- TODO: this should be fixed for multi-tenant deployment
  local has_configuration = configuration.configured
  local has_services = #(configuration:all()) > 0

  if not has_configuration then
    return { status = 'error', error = 'not configured',  success = false }
  elseif not has_services then
    return { status = 'warning', warning = 'no services', success = true }
  else
    return { status = 'ready', success = true }
  end
end

function _M.config()
  local config = context_configuration()
  local contents = cjson.encode(config.configured and { services = config:all() } or nil)

  ngx.header.content_type = 'application/json; charset=utf-8'
  ngx.status = ngx.HTTP_OK
  ngx.say(contents)
end

function _M.update_config()
  ngx.req.read_body()

  ngx.log(ngx.DEBUG, 'management config update')
  local data = ngx.req.get_body_data()
  local file = ngx.req.get_body_file()

  if not data then
    data = assert(io.open(file)):read('*a')
  end

  local config, err = configuration_parser.decode(data)

  if config then
    local configured, error = configuration_loader.configure(context_configuration(), config)
    -- TODO: respond with proper 304 Not Modified when config is the same
    if configured and #(configured.services) > 0 then
      json_response({ status = 'ok', config = config, services = #(configured.services)})
    else
      json_response({ status = 'not_configured', config = config, services = 0, error = error }, ngx.HTTP_NOT_ACCEPTABLE)
    end
  else
    json_response({ status = 'error', config = config or cjson.null, error = err}, ngx.HTTP_BAD_REQUEST)
  end
end

function _M.delete_config()
  ngx.log(ngx.DEBUG, 'management config delete')

  context_configuration():reset()
  -- TODO: respond with proper 304 Not Modified when config is the same
  local response = cjson.encode({ status = 'ok', config = cjson.null })
  ngx.header.content_type = 'application/json; charset=utf-8'
  ngx.say(response)
end

local util = require 'apicast.util'

function _M.boot()
  local data = util.timer('configuration.boot', configuration_loader.boot)
  local config = configuration_parser.decode(data)
  local response = cjson.encode({ status = 'ok', config = config or cjson.null })

  ngx.log(ngx.DEBUG, 'management boot config:' .. inspect(data))

  configuration_loader.configure(context_configuration(), config)

  ngx.say(response)
end

function _M.dns_cache()
  local cache = resolver_cache.shared()
  return json_response(cache:all())
end

function _M.disabled()
  ngx.exit(ngx.HTTP_FORBIDDEN)
end

function _M.info()
  return json_response({
    timers = {
      pending = ngx.timer.pending_count(),
      running = ngx.timer.running_count()
    },
    worker = {
      exiting = ngx.worker.exiting(),
      count = ngx.worker.count(),
      id = ngx.worker.id()
    }
  })
end

function _M.get_all_policy_manifests()
  local manifests = policy_manifests_loader.get_all()
  return json_response({ policies = manifests })
end

local routes = {}

function routes.disabled(r)
  r:get('/', _M.disabled)
end

function routes.status(r)
  r:get('/status/info', _M.info)
  r:get('/status/ready', _M.ready)
  r:get('/status/live', _M.live)

  routes.policies(r)
end

function routes.debug(r)
  r:get('/config', _M.config)
  r:put('/config', _M.update_config)
  r:post('/config', _M.update_config)
  r:delete('/config', _M.delete_config)

  routes.status(r)

  r:get('/dns/cache', _M.dns_cache)

  r:post('/boot', _M.boot)

  routes.policies(r)
end

function routes.policies(r)
  r:get('/policies/', _M.get_all_policy_manifests)
end

function _M.router(name)
  local r = router.new()

  local mode = name or env.value('APICAST_MANAGEMENT_API') or 'status'
  local api = routes[mode]

  ngx.log(ngx.DEBUG, 'management api mode: ', mode)

  if api then
    api(r)
  else
    ngx.log(ngx.ERR, 'invalid management api setting: ', mode)
  end

  return r
end

function _M.call(method, uri, ...)
  local r = _M.router()

  local ok, err = r:execute(method or ngx.req.get_method(),
                                 uri or ngx.var.uri,
                                 unpack(... or {}))

  if not ok then
    ngx.status = 404
  end

  if err then
    ngx.say(err)
  end
end

return _M
