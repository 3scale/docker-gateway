-- This is a standalone description.

local Policy = require('apicast.policy')
local PolicyChain = require('apicast.policy_chain')
local Upstream = require('apicast.upstream')
local balancer = require('apicast.balancer')
local Configuration = require('apicast.policy.standalone.configuration')
local resty_env = require('resty.env')
local _M = Policy.new('standalone')
local tab_new = require('resty.core.base').new_tab
local insert = table.insert
local pairs = pairs
local assert = assert
local format = string.format
local concat = table.concat

local setmetatable = setmetatable

local function load_configuration(url)
  local configuration, err = Configuration.new(url)

  if configuration then
    configuration, err = configuration:load()
  end

  return configuration, err
end

local new = _M.new
--- Initialize the Standalone APIcast policy
-- @tparam[opt] table config Policy configuration.
function _M.new(config)
  local self = new(config)

  self.url = (config and config.url) or resty_env.get('APICAST_CONFIGURATION')

  return self
end


local empty_chain = PolicyChain.new()

-- forward all policy request methods to the policy chain
for _,phase in Policy.request_phases() do
  _M[phase] = function(self, context, ...)
    if context[self] then
      return context[self][phase](context[self], context, ...)
    end
  end
end

local function build_objects(constructor, list)
  if not list then return {} end

  local objects = tab_new(#list, 0)

  for i=1, #list do
    local object = constructor(list[i])

    if object.name then
      objects[object.name] = object
    end

    objects[i] = object
  end

  return objects
end

local Route = { }

local function build_routes(configuration)
  return build_objects(Route.new, configuration.routes)
end

local Destination = { }
do
  local Destination_mt = { __index = Destination }

  function Destination.new(config)
    if not config then return nil end

    return setmetatable({
      service = config.service,
      upstream = config.upstream,
      http_response = config.http_response,
    }, Destination_mt)
  end
end

local Condition = { }
do

  local Condition_mt = { __index = Condition }

  local operations = {
    server_port = function(self) return
      ngx.var.server_name == self.value or ngx.var.server_port == self.value
    end,
    uri_path = function(self) return ngx.var.uri == self.value end,
    http_method = function(self) return ngx.req.get_method() == self.value end,
    http_host = function(self) return ngx.var.host == self.value end,
    always = function(self) return self.value end,
    unknown = function(self) ngx.log(ngx.ERR, 'unknown condition ', self.name); return end
  }

  function Condition.new(name, value)
    return setmetatable({
        fun = operations[name] or operations.unknown,
        value = value,
        name = name,
    }, Condition_mt)
  end

  function Condition:match(context)
    local res = self:fun(context)

    ngx.log(ngx.DEBUG, 'condition ', self.name, ' == ', self.value, ' : ', res)

    return res
  end
end

local Match = { }
do
  local Match_mt = { __index = Match }

  function Match.new(config)
    local matchers = { }

    for name, value in pairs(config) do
      insert(matchers, Condition.new(name, value))
    end

    return setmetatable(matchers, Match_mt)
  end

  function Match:any(context)
    for i=1, #self do
      if self[i]:match(context) then
        return self[i]
      end
    end
  end

  function Match:all(context)
    for i=1, #self do
      if not self[i]:match(context) then
        return false
      end
    end

    return true
  end
end

do
  local Route_mt = {
    __index = Route,
    __tostring = function(route)
      local match = tab_new(#route.conditions, 0)

      for i=1, #route.conditions do
        match[i] = format("%s = %s", route.conditions[i].name, route.conditions[i].value)
      end

      return format('%s', concat(match, ' and '))
    end
  }

  function Route.new(config)
    return setmetatable({
      name = config.name,
      conditions = Match.new(config.match),
      destination = Destination.new(assert(config.destination, 'route is missing destination')),
      routes = build_routes(config),
    }, Route_mt)
  end

  function Route:match(context)
    return self.conditions:all(context)
  end
end

local Service = { }

local function build_services(configuration)
  return build_objects(Service.new, configuration.internal)
end

do
  local Service_mt = { __index = Service }

  local function build_policy_chain(policies)
    local chain = PolicyChain.new()

    for i=1, #policies do
      chain:add_policy(policies[i].policy, policies[i].version, policies[i].configuration)
    end

    return chain
  end

  function Service.new(config)
    return setmetatable({
      name = config.name,
      upstream = Upstream.new(config.upstream),
      policy_chain = build_policy_chain(config.policy_chain),
    }, Service_mt)
  end
end

local External = { }

local function build_upstreams(configuration)
  return build_objects(External.new, configuration.external)
end

do
  local External_mt = { __index = External }

  local UpstreamPolicy = Policy.new('Standalone Upstream Policy')
  local UpstreamPolicy_new = UpstreamPolicy.new

  function UpstreamPolicy.new(config)
    local self = UpstreamPolicy_new(config)
    self.upstream = Upstream.new(config.server)
    return self
  end

  function UpstreamPolicy:content(context)
    context[self] = self.upstream
    self.upstream:call(context)
  end

  UpstreamPolicy.balancer = balancer.call

  function External.new(config)
    local upstream_policy = UpstreamPolicy.new(config)
    local upstream = upstream_policy.upstream
    local policy_chain = PolicyChain.new({ upstream_policy }):freeze()

    return setmetatable({
      name = config.name,
      server = upstream,
      load_balancer = config.load_balancer,
      policy_chain = policy_chain,
      retries = config.retries,
    }, External_mt)
  end
end

local default = {
  services = build_objects(Service.new, {
    { name = 'not_found',
      policy_chain = {
        { policy = 'apicast.policy.echo', configuration = { status = ngx.HTTP_NOT_FOUND } },
      },
    },
  }),
}

function _M:load_configuration()
  local url = self.url

  if not url then
    return nil, 'not initialized'
  end

  local configuration, err = load_configuration(url)

  if configuration then
    self.routes = build_routes(configuration)
    self.services = setmetatable(build_services(configuration), { __index = default.services })
    self.upstreams = build_upstreams(configuration)

    ngx.log(ngx.DEBUG, 'loaded standalone configuration from: ', url, ' ', configuration)
    return configuration
  else
    ngx.log(ngx.WARN, 'failed to load ', url, ' err: ', err)

    self.routes = {}
    self.services = setmetatable({}, { __index = default.services })
    self.upstreams = {}

    return nil, err
  end
end

local function run_phase(phase, services, ...)
  if not services then return end

  for _, service in ipairs(services) do
    ngx.log(ngx.DEBUG, 'running phase ', phase, ' on service ', service.name)
    service.policy_chain[phase](service.policy_chain, ...)
  end
end

function _M:init(...)
  if self then -- initializing policy instance
    local config, err = self:load_configuration(self)

    if config then
      -- TODO: we need to run this because some policies are "internal" and not being
      -- found and executed by the apicast.executor :init phase.
      -- However, this means some policies get .init called twice (or multiple times)
      -- and need to be changed to initialize only once (like starting timers).
      run_phase('init', self.services, ...)
      return config
    else
        return nil, err
    end
  end
end

function _M:init_worker(...)
  run_phase('init_worker', self.services, ...)
end

local find_route, match_route
match_route = function (route, context)
  ngx.log(ngx.DEBUG, 'testing route: ', route)
  if route:match(context) then
    ngx.log(ngx.DEBUG, 'route matched: ', route)
    if route.routes then
      return find_route(route.routes) or route
    else
      return route
    end
  end
end

find_route = function (routes, context)
  if not routes then return end

  for i=1, #routes do
    local route = match_route(routes[i], context)
    if route then return route end
  end
end

local function find_service(self, route)
  local destination = route and route.destination

  if not destination then return nil, 'no destination' end

  if destination.service then
    return self.services[destination.service]
  end

  if destination.upstream then
    local upstream = self.upstreams[destination.upstream]

    if upstream then
      return upstream
    else
      return nil, 'upstream not found'
    end
  end

  return nil, 'destination not found'
end

local function not_found(self)
  return assert(self.services.not_found, 'missing service: not_found').policy_chain
end

function _M:dispatch(route)
  if not route then
    ngx.log(ngx.ERR, 'route not found')
    return not_found(self)
  end

  local service, err = find_service(self, route)

  if service then
    return service.policy_chain or empty_chain
  else
    ngx.log(ngx.ERR, 'could not find the route destination: ', err)
    return not_found(self)
  end
end

local rewrite = _M.rewrite

function _M:rewrite(context)
  local route = find_route(self.routes, context)

  context[self] = assert(self:dispatch(route), 'missing policy chain')

  return rewrite(self, context)
end

return _M
