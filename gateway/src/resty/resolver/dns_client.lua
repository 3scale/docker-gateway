local resty_resolver = require 'resty.dns.resolver'

local setmetatable = setmetatable
local insert = table.insert

local _M = {
  _VERSION = '0.1'
}
local mt = { __index = _M }

function _M.new(_, options)
  local resolvers = {}
  local opts = options or {}
  local nameservers = opts.nameservers or {}

  return setmetatable({
    initialized = false,
    resolvers = resolvers,
    nameservers = nameservers
  }, mt)
end

function _M:instance(nameservers)
  local ctx = ngx.ctx
  local resolver = ctx.dns

  if not resolver then
    resolver = self:new({ nameservers = nameservers })
  end

  -- This condition is a bit hacky, but when using UDP cosockets on ssl_cert
  -- phase, it'll be closed for other phases, so skip to share on the ssl_cert
  -- case.
  -- Check THREESCALE-7230 for more info.
  if ngx.get_phase() ~= "ssl_cert" then
    ctx.dns = resolver
  end

  return resolver
end

function _M:init_resolvers()
  local resolvers = self.resolvers
  local ns = self.nameservers

  if not resolvers or not ns then
    return nil, 'not initialized'
  end

  ngx.log(ngx.DEBUG, 'initializing ', #ns, ' nameservers')

  for i=1,#ns do
    local resolver, err = resty_resolver:new({
      nameservers = { ns[i] },
      timeout = 2900
    })

    if resolver then
      insert(resolvers, {
        nameserver = ns[i],
        resolver = resolver
      })
      ngx.log(ngx.DEBUG, 'nameserver ', ns[i][1],':',ns[i][2] or 53, ' initialized')
    else
      ngx.log(ngx.WARN, 'nameserver ', ns[i][1],':',ns[i][2] or 53, ' not initialized: ', err)
    end
  end

  self.initialized = true

  return resolvers
end

local function query(resolver, qname, opts, nameserver)
  ngx.log(ngx.DEBUG, 'resolver query: ', qname, ' nameserver: ', nameserver[1],':', nameserver[2] or 53)
  return resolver:query(qname, opts)
end

local function serial_query(resolvers, qname, opts)
  local answers, err

  for i=1, #resolvers do
    answers, err = query(resolvers[i].resolver, qname, opts, resolvers[i].nameserver)

    if answers and not answers.errcode and not err then
      break
    end
  end

  return answers
end

function _M.query(self, qname, opts)
  local resolvers = self.resolvers

  if not self.initialized then
    resolvers = self:init_resolvers()
  end

  return serial_query(resolvers, qname, opts)
end

return _M
