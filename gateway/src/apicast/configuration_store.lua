local setmetatable = setmetatable
local pairs = pairs
local insert = table.insert
local concat = table.concat
local rawset = rawset
local lower = string.lower

local env = require 'resty.env'
local lrucache = require 'resty.lrucache'

local _M = {
  _VERSION = '0.1',
  path_routing = env.enabled('APICAST_PATH_ROUTING') or env.enabled('APICAST_PATH_ROUTING_ENABLED') or
                 env.enabled('APICAST_PATH_ROUTING_ONLY'),
  path_routing_only = env.enabled('APICAST_PATH_ROUTING_ONLY'),
  cache_size = tonumber(env.value('APICAST_SERVICE_CACHE_SIZE')) or 1000
}

if env.enabled('APICAST_PATH_ROUTING_ENABLED') then ngx.log(ngx.WARN, 'DEPRECATION NOTICE: Use APICAST_PATH_ROUTING not APICAST_PATH_ROUTING_ENABLED as this will soon be unsupported') end

local mt = { __index = _M, __tostring = function() return 'Configuration Store' end }

function _M.new(cache_size, options)
  local path_routing, path_routing_only

  if options and options.path_routing ~= nil then
    path_routing = options.path_routing
  else
    path_routing = _M.path_routing
  end

  if options and options.path_routing_only ~= nil then
    path_routing_only = options.path_routing_only
  else
    path_routing_only = _M.path_routing_only
  end
  return setmetatable({
    -- services hashed by id, example: {
    --   ["16"] = service1
    -- }
    services = lrucache.new(cache_size or _M.cache_size),

    -- hash of hosts pointing to services, example: {
    --  ["host.example.com"] = {
    --    { service1 },
    --    { service2 }
    --  }
    cache = lrucache.new(cache_size or _M.cache_size),

    path_routing = path_routing,
    path_routing_only = path_routing_only,

    cache_size = cache_size

  }, mt)
end

function _M.all(self)
  local all = self.services
  local services = {}

  if not all then
    return nil, 'not initialized'
  end

  for _,v in pairs(all.hasht) do
    insert(services, v.serializable or v)
  end

  return services
end

function _M.find_by_id(self, service_id)
  local all = self.services

  if not all then
    return nil, 'not initialized'
  end

  return all:get(service_id)
end

function _M.find_by_host(self, host, stale)
  local cache = self.cache
  if not cache then
    return nil, 'not initialized'
  end

  if stale == nil then
    stale = true
  end

  local services, expired = cache:get(host)

  if expired and stale then
    ngx.log(ngx.INFO, 'using stale configuration for host ', host)
  end

  return services or (stale and expired) or { }
end

local hashed_array = {
  __index = function(t,k)
    local v = {}
    rawset(t,k, v)
    return v
  end
}

function _M.store(self, config, ttl)
  self.configured = true

  local services = config.services or {}
  local by_host = setmetatable({}, hashed_array)
  local oidc = config.oidc or {}

  local ids = {}

  for i=1, #services do
    local service = services[i]
    local hosts = service.hosts or {}
    local id = service.id

    if oidc[i] ~= ngx.null then
      -- merge service and OIDC config, this is far from ideal, but easy for now
      for k,v in pairs(oidc[i] or {}) do
        service.oidc[k] = v
      end
    end

    if not ids[id] then
      ngx.log(ngx.INFO, 'added service ', id, ' configuration with hosts: ', concat(hosts, ', '), ' ttl: ', ttl)

      for j=1, #hosts do
        local host = lower(hosts[j])
        local h = by_host[host]

        if #(h) == 0 or self.path_routing then
          insert(h, service)
        else
          ngx.log(ngx.WARN, 'skipping host ', host, ' for service ', id, ' already defined by service ', h[1].id)
        end
      end

      self.services:set(id, services[i]) -- FIXME: no ttl here, is that correct assumption?
      ids[id] = services[i]
    else
      ngx.log(ngx.WARN, 'skipping service ', id, ' becasue it is a duplicate')
    end
  end

  local cache = self.cache

  local cache_ttl = config.ttl or ttl or _M.ttl

  -- In lrucache a value < 0 expires, but we use configs and ENVs for
  -- setting the ttl where < 0 means 'never expire'. When ttl < 0,
  -- we need to set it to nil (never expire in lrucache).
  if cache_ttl and cache_ttl < 0 then cache_ttl = nil end

  for host, services_for_host in pairs(by_host) do
    cache:set(host, services_for_host, cache_ttl)
  end

  return config
end

function _M.reset(self, cache_size)
  if not self.services then
    return nil, 'not initialized'
  end

  self.services = lrucache.new(cache_size or _M.cache_size)
  self.cache = lrucache.new(cache_size or _M.cache_size)
  self.configured = false
end

function _M.add(self, service, ttl)
  if not self.services then
    return nil, 'not initialized'
  end

  return self:store({ services = { service }}, ttl)
end

return _M
