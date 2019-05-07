local setmetatable = setmetatable
local insert = table.insert
local tonumber = tonumber

local _M = {
  _VERSION = '0.1'
}

local mt = { __index = _M }

do
  local ngx_balancer = require "ngx.balancer"

  function _M.new(mode)
    if not mode then
      return nil, 'missing balancing function'
    end

    return setmetatable({
      mode = mode,
      balancer = ngx_balancer
    }, mt)
  end
end

local function new_peer(server, port)
  local address = server.address

  if not address then
    return nil, 'server missing address'
  end

  return {
    address,
    tonumber(server.port or port, 10)
  }
end

local function convert_servers(servers, port)
  local peers = {}
  local query = servers.query

  for i =1, #servers do
    local peer = new_peer(servers[i], port)

    if peer then
      insert(peers, peer)
    else
      ngx.log(ngx.INFO, 'skipping peer because it misses address or port')
    end
  end

  if query then
    peers.hash = ngx.crc32_short(query)
  end

  peers.servers = servers

  return peers
end

function _M.peers(_, servers, port)
  if not servers then
    return nil, 'missing servers'
  end

  local peers, err = convert_servers(servers, port)

  return peers, err
end

function _M.select_peer(self, peers)
  local mode = self.mode

  if not mode then
    return nil, 'not initialized'
  end

  if not peers then
    return nil, 'missing peers'
  end

  local peer, err = mode(peers)

  if not peer then
    return nil, err or  'no peer found'
  end

  return peer
end

function _M:set_current_peer(address, port)
  local ngx_balancer = self.balancer

  if not ngx_balancer then
    return nil, 'balancer not available'
  end

  if not address then
    return nil, 'peer missing address'
  end

  if not port then
    return nil, 'peer missing port'
  end

  local ok, err = ngx_balancer.set_current_peer(address, port)
  ngx.log(ngx.INFO, 'balancer set peer ', address, ':', port, ' ok: ', ok, ' err: ', err)

  if ok then
    return true
  else
    return nil, err or 'balancer could not set the peer'
  end
end

function _M.set_peer(self, peers)
  local balancer = self.balancer

  if not balancer then
    return nil, 'balancer not available'
  end

  local peer, err = self:select_peer(peers)

  if peer then
    local ok
    ok, err = self:set_current_peer(peer[1], peer[2])

    if ok then
      return peer
    else
      return nil, err
    end
  else
    return nil, err or 'no peer found'
  end
end

function _M:set_timeouts(connect_timeout, send_timeout, read_timeout)
  local ngx_balancer = self.balancer

  if not ngx_balancer then
    return nil, 'balancer not available'
  end

  -- If one of the values is nil, the default applies:
  -- https://github.com/openresty/lua-resty-core/blob/master/lib/ngx/balancer.md#set_timeouts
  return ngx_balancer.set_timeouts(connect_timeout, send_timeout, read_timeout)
end

return _M
