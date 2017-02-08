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

function _M:init_resolvers()
  local resolvers = self.resolvers
  local nameservers = self.nameservers

  for i=1,#nameservers do
    insert(resolvers, { nameservers[i], resty_resolver:new({ nameservers = { nameservers[i] }}) })
  end

  self.initialized = true

  return resolvers
end

function _M.query(self, qname, opts)
  local resolvers = self.resolvers
  local answers, err

  if not self.initializeed then
    resolvers = self:init_resolvers()
  end

  for i=1, #resolvers do
    answers, err = resolvers[i][2]:query(qname, opts)

    ngx.log(ngx.DEBUG, 'resolver query: ', qname, ' nameserver: ', resolvers[i][1][1],':', resolvers[i][1][2])

    if answers and not answers.errcode and not err then
      break
    end
  end

  return answers, err
end

return _M
