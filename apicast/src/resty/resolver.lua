local setmetatable = setmetatable
local next = next
local open = io.open
local gmatch = string.gmatch
local match = string.match
local insert = table.insert
local getenv = os.getenv
local concat = table.concat
local io_type = io.type
local re_match = ngx.re.match
local semaphore = require "ngx.semaphore"
local resolver_cache = require 'resty.resolver.cache'

local init = semaphore.new(1)

local default_resolver_port = 53

local _M = {
  _VERSION = '0.1',
  _nameservers = {},
  search = {}
}

local mt = { __index = _M }

function _M.parse_nameservers(path)
  local search = {}
  local nameservers = { search = search }
  local resolver = getenv('RESOLVER')

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
  else
    ngx.log(ngx.ERR, 'resolver could not get nameservers: ', err)
    return nil, err
  end
  ngx.log(ngx.DEBUG, '/etc/resolv.conf:\n', output)

  local domains = match(output, 'search%s+([^\n]+)')
  ngx.log(ngx.DEBUG, 'search ', domains)
  for domain in gmatch(domains or '', '([^%s]+)') do
    ngx.log(ngx.DEBUG, 'search domain: ', domain)
    insert(search, domain)
  end

  if resolver then
    insert(nameservers, { resolver })
  end

  for nameserver in gmatch(output, 'nameserver%s+([^%s]+)') do
    -- TODO: implement port matching based on https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=549190
    local port = default_resolver_port
    if nameserver ~= resolver then
      insert(nameservers, { nameserver, port } )
    end
  end

  return nameservers
end

function _M.init_nameservers()
  local nameservers = _M.parse_nameservers() or {}
  local search = nameservers.search or {}

  for i=1, #nameservers do
    ngx.log(ngx.INFO, 'adding ', nameservers[i][1],':', nameservers[i][2], ' as default nameserver')
    insert(_M._nameservers, nameservers[i])
  end

  for i=1, #search do
    ngx.log(ngx.INFO, 'adding ', search[i], ' as search domain')
    insert(_M.search, search[i])
  end
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

function _M.init()
  _M.init_nameservers()
end

function _M.new(dns, opts)
  opts = opts or {}
  local cache = opts.cache or resolver_cache.new()
  local search = opts.search or _M.search

  ngx.log(ngx.DEBUG, 'resolver search domains: ', concat(search, ' '))

  return setmetatable({
    dns = dns,
    cache = cache,
    search = search
  }, mt)
end


local function new_server(answer, port)
  local address = answer.address
  if not address then return nil, 'server missing address' end

  return {
    address = answer.address,
    ttl = answer.ttl,
    port = answer.port or port
  }
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

local function has_tld(qname)
  return match(qname, '%.')
end

local function have_addresses(answers)
  return answers and next(answers.addresses or {}) and #answers > 0 and not answers.errcode
end

local function convert_answers(answers, port)
  local servers = {}

  for i=1, #answers do
    servers[#servers+1] = new_server(answers[i], port)
  end

  servers.answers = answers

  return servers
end

function _M.get_servers(self, qname, opts)
  opts = opts or {}
  local dns = self.dns
  local port = opts.port
  local cache = self.cache
  local search = self.search or {}

  if not dns then
    return nil, 'resolver not initialized'
  end

  if not qname then
    return nil, 'query missing'
  end

  -- TODO: implement cache
  -- TODO: pass proper options to dns resolver (like SRV query type)

  local answers, err = cache:get(qname)

  if not answers or #answers.addresses == 0 then
    ngx.log(ngx.DEBUG, 'resolver query: ', qname)

    if is_ip(qname) then
      ngx.log(ngx.DEBUG, 'host is ip address: ', qname)
      answers = { new_answer(qname) }
    else
      answers, err = dns:query(qname, { qtype = dns.TYPE_A })

      if not has_tld(qname) and not have_addresses(answers) then
        for i=1, #search do

          local query = qname .. '.' .. search[i]
          ngx.log(ngx.DEBUG, 'resolver query: ', qname, ' search: ', search[i], ' query: ', query)
          answers, err = dns:query(query, { qtype = dns.TYPE_A })

          if answers and not answers.errcode and #answers > 0 then break end
        end
      end
    end

    cache:save(answers)
  end

  if err then
    return {}, err
  end

  if not answers then
    return {}, 'no answers'
  end

  local servers = convert_answers(answers, port)

  servers.query = qname

  return servers
end

return _M
