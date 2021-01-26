local setmetatable = setmetatable
local next = next
local open = io.open
local gmatch = string.gmatch
local match = string.match
local sub = string.sub
local format = string.format
local find = string.find
local insert = table.insert
local concat = table.concat
local io_type = io.type

require('resty.core.regex') -- to allow use of ngx.re.match in the init phase

local re_match = ngx.re.match
local resolver_cache = require 'resty.resolver.cache'
local dns_client = require 'resty.resolver.dns_client'
local resty_env = require 'resty.env'
local upstream = require 'ngx.upstream'
local re = require('ngx.re')
local semaphore = require "ngx.semaphore"
local synchronization = require('resty.synchronization').new(1)

local init = semaphore.new(1)

local default_resolver_port = 53

local _M = {
  _VERSION = '0.1',
}

local mt = { __index = _M }

local function read_resolv_conf(path)
  path = path or '/etc/resolv.conf'

  local handle, err

  if io_type(path) then
    handle = path
  else
    handle, err = open(path)
  end

  local output

  if handle then
    handle:seek("set")
    output = handle:read("*a")
    handle:close()
  end

  return output or "", err
end

local function ipv4(address)
  return re_match(address, '^([0-9]{1,3}\\.){3}[0-9]{1,3}$', 'oj')
end

local function ipv6(address)
  return re_match(address, '^\\[[a-f\\d:]+\\]$', 'oj')
end

local nameserver = {
  mt = {
    __tostring = function(t)
      return concat(t, ':')
    end
  }
}

function nameserver.new(host, port)
  if not ipv4(host) and not ipv6(host) then
    -- then it is likely ipv6 without [ ] around
    host = format('[%s]', host)
  end
  return setmetatable({ host, port or default_resolver_port }, nameserver.mt)
end

function _M.reset()
  _M._nameservers = {}
  _M.search = { '' }
  return _M
end

function _M.parse_resolver(resolver)
  if not resolver then return end

  local m, err = re_match(resolver, [[^
      (
        (?:\d{1,3}\.){3}\d{1,3} # ipv4
        |
        \[[a-f\d:]+\] # ipv6 in [ ] brackes, like [dead::beef]
        |
        [a-f\d:]+ # ipv6 without brackets
      )
      (?:\:(\d+))? # optional port
    $]], 'ojx')

  if m then
    return nameserver.new(m[1], m[2])
  else
    return resolver, err or 'invalid address'
  end
end


function _M.parse_nameservers(path)
  local resolv_conf, err = read_resolv_conf(path)

  if err then
    ngx.log(ngx.NOTICE, 'resolver could not get nameservers: ', err)
  end

  ngx.log(ngx.DEBUG, '/etc/resolv.conf:\n', resolv_conf)

  local search = { }
  local nameservers = { search = search }

  local resolver
  resolver, err = _M.parse_resolver(resty_env.value('RESOLVER'))

  if err then
    ngx.log(ngx.ERR, 'invalid resolver ', resolver, ' error: ', err)
  elseif resolver then
    -- we are going to use all resolvers, because we can't trust dnsmasq
    -- see https://github.com/3scale/apicast/issues/321 for more details
    insert(nameservers, resolver)
  end

  for _,line in ipairs(re.split(resolv_conf, "\n+")) do

    local domains = match(line, '^search%s+([^\n]+)')

    if domains then
      ngx.log(ngx.DEBUG, 'search ', domains)

      for domain in gmatch(domains or '', '([^%s]+)') do
        if match(domain, '^%#') then break end
        ngx.log(ngx.DEBUG, 'search domain: ', domain)
        insert(search, domain)
      end
    end

    local server = match(line, '^nameserver%s+([^%s]+)')
    -- TODO: implement port matching based on https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=549190
    --       meanwhile assuming default port 53.
    if server and format("%s:%s", server, default_resolver_port) ~= tostring(resolver) then
      insert(nameservers, nameserver.new(server))
    end
  end

  return nameservers
end

function _M.init_nameservers(path)
  local nameservers = _M.parse_nameservers(path) or {}
  local search = nameservers.search or {}

  for i=1, #nameservers do
    ngx.log(ngx.INFO, 'adding ', nameservers[i], ' as default nameserver')
    insert(_M._nameservers, nameservers[i])
  end

  for i=1, #search do
    ngx.log(ngx.INFO, 'adding ', search[i], ' as search domain')
    insert(_M.search, search[i])
  end

  return nameservers
end

function _M.nameservers()
  local ok, _ = init:wait(0)

  if ok and #(_M._nameservers) == 0 then
    _M.init()
  end

  if ok then
    init:post()
  end

  return _M._nameservers
end

function _M.init(path)
  _M.init_nameservers(path)
end

function _M.new(dns, opts)
  opts = opts or {}
  local cache = opts.cache or resolver_cache.shared()
  local search = opts.search or _M.search

  ngx.log(ngx.DEBUG, 'resolver search domains: ', concat(search, ' '))

  return setmetatable({
    dns = dns,
    options = { qtype = dns.TYPE_A },
    cache = cache,
    search = search
  }, mt)
end

function _M:instance()
  local ctx = ngx.ctx
  local resolver = ctx.resolver

  if not resolver then
    local dns = dns_client:instance(self.nameservers())
    resolver = self.new(dns)
    ctx.resolver = resolver
  end

  return resolver
end

local server_mt = {
  __tostring = function(t)
    return format('%s:%s', t.address, t.port)
  end
}

local function new_server(answer, port)
  if not answer then return nil, 'missing answer' end
  local address = answer.address
  if not address then return nil, 'server missing address' end

  return setmetatable({
    address = answer.address,
    ttl = answer.ttl,
    port = port or answer.port,
  }, server_mt)
end

local function new_answer(address, port)
  return {
    address = address,
    ttl = -1,
    port = port
  }
end

local function is_ip(address)
  local m, err = re_match(address, '^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$', 'oj')

  if m then
    return next(m)
  else
    return nil, err
  end
end

local function is_fqdn(name)
  return find(name, '.', 1, true)
end

local servers_mt = {
  __tostring = function(t)
    return concat(t, ' ')
  end
}

local function convert_answers(answers, port)
  local servers = {}

  for i=1, #answers do
    servers[#servers+1] = new_server(answers[i], port)
  end

  servers.answers = answers

  return setmetatable(servers, servers_mt)
end

local empty = {}

local function valid_answers(answers)
  return answers and not answers.errcode and #answers > 0 and (not answers.addresses or #answers.addresses > 0)
end

local function search_dns(self, qname, stale)

  local search = self.search
  local dns = self.dns
  local options = self.options
  local cache = self.cache

  local function get_answer(query)
    local answers, err
    answers, err = cache:get(query, stale)
    if valid_answers(answers) then
      return answers, err
    end

    answers, err = dns:query(query, options)
    if valid_answers(answers) then
      cache:save(answers)
      return answers, err
    end
    return nil, err
  end

  if sub(qname, -1) == "." then
    local query = sub(qname, 1 ,-2)
    ngx.log(ngx.DEBUG, 'resolver query: ', qname, ' query: ', query)
    return get_answer(query)
  end

  local answer, err
  for i=1, #search do
    local query = qname .. '.' .. search[i]
    ngx.log(ngx.DEBUG, 'resolver query: ', qname, ' search: ', search[i], ' query: ', query)
    answer, err = get_answer(query)
    if answer then
      return answer, err
    end
  end

  return nil, err
end

local function resolve_upstream(qname)
  local peers, err = upstream.get_primary_peers(qname)

  if not peers then
    return nil, err
  end

  for i=1, #peers do
    local m = re.split(peers[i].name, ':', 'oj')

    peers[i] = new_answer(m[1], m[2])
  end

  return peers
end

function _M.lookup(self, qname, stale)
  local cache = self.cache

  ngx.log(ngx.DEBUG, 'resolver query: ', qname)

  local answers, err

  if is_ip(qname) then
    ngx.log(ngx.DEBUG, 'host is ip address: ', qname)
    answers = { new_answer(qname) }
  else
    if is_fqdn(qname) then
      answers, err = cache:get(qname, stale)
    else
      answers, err = resolve_upstream(qname)
    end

    if not valid_answers(answers) then
      answers, err = search_dns(self, qname, stale)
    end

  end

  ngx.log(ngx.DEBUG, 'resolver query: ', qname, ' finished with ', #(answers or empty), ' answers')

  return answers, err
end

function _M.get_servers(self, qname, opts)
  opts = opts or {}
  local dns = self.dns

  if not dns then
    return nil, 'resolver not initialized'
  end

  if not qname then
    return nil, 'query missing'
  end

  -- TODO: pass proper options to dns resolver (like SRV query type)

  local sema, key = synchronization:acquire(format('qname:%s:qtype:%s', qname, 'A'))
  local ok = sema:wait(0)

  local answers, err = self:lookup(qname, not ok)

  if ok then
    -- cleanup the key so we don't have unbounded growth of this table
    synchronization:release(key)
    sema:post()
  end

  if err then
    ngx.log(ngx.DEBUG, 'query for ', qname, ' finished with error: ', err)
    return {}, err
  end

  if not answers then
    ngx.log(ngx.DEBUG, 'query for ', qname, ' finished with no answers')
    return {}, 'no answers'
  end

  ngx.log(ngx.DEBUG, 'query for ', qname, ' finished with ' , #answers, ' answers')

  local servers = convert_answers(answers, opts.port)

  servers.query = qname

  return servers
end

return _M.reset()
