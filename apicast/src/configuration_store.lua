local setmetatable = setmetatable
local ipairs = ipairs
local pairs = pairs
local insert = table.insert
local concat = table.concat
local next = next

local env = require 'resty.env'

local _M = {
  _VERSION = '0.1',
  path_routing = env.enabled('APICAST_PATH_ROUTING_ENABLED')
}

local mt = { __index = _M }

function _M.new()
  return setmetatable({
    services = {},
    hosts = {}
  }, mt)
end

function _M.all(self)
  local all = self.services
  local services = {}

  if not all then
    return nil, 'not initialized'
  end

  for _,service in pairs(all) do
    insert(services, service.serializable or service)
  end

  return services
end

function _M.find(self, host)
  local hosts = self.hosts
  local all = self.services

  if not hosts or not all then
    return nil, 'not initialized'
  end

  local exact_match = all[host]

  if exact_match then
    return { exact_match }
  end

  return hosts[host] or { }
end

function _M.store(self, config)
  self.configured = true
  local services = config.services

  for i = 1, #services do
    _M.add(self, services[i])
  end

  return config
end

function _M.reset(self)
  if not self then
    return nil, 'not initialized'
  end

  self.services = {}
  self.hosts = {}
  self.configured = false
end

function _M.add(self, service)
  local hosts = self.hosts
  local all = self.services

  if not hosts or not all then
    return nil, 'not initialized'
  end

  local id = service.id

  for _,host in ipairs(service.hosts) do
    local index = hosts[host] or {}
    local exists = not _M.path_routing and next(index)

    index[id] = service
    all[id] = service
    hosts[host] = index

    if exists and exists ~= id then
      ngx.log(ngx.WARN, 'host ', host, ' for service ', id, ' already defined by service ', exists)
    end
  end

  ngx.log(ngx.INFO, 'added service ', id, ' configuration with hosts: ', concat(service.hosts, ', '))
end

return _M
