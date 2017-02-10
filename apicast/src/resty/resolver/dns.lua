local resty_resolver = require 'resty.dns.resolver'
local newrelic = require 'resty.newrelic'

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

  local nr_transaction_id = ngx.ctx.nr_transaction_id or ngx.var.nr_transaction_id
  local resolver_segment_id = nr_transaction_id and newrelic.begin_generic_segment(nr_transaction_id, newrelic.NEWRELIC_ROOT_SEGMENT, 'initialize resolver')

  for i=1,#nameservers do
    insert(resolvers, { nameservers[i], resty_resolver:new({ nameservers = { nameservers[i] }}) })
  end

  newrelic.end_segment(nr_transaction_id, resolver_segment_id)

  self.initialized = true

  return resolvers
end

function _M.query(self, qname, opts)
  local resolvers = self.resolvers
  local answers, err

  if not self.initializeed then
    resolvers = self:init_resolvers()
  end

  local nr_transaction_id = ngx.ctx.nr_transaction_id
  local dns_segment_id = newrelic.begin_generic_segment(nr_transaction_id, newrelic.NEWRELIC_ROOT_SEGMENT, 'dns query')

  for i=1, #resolvers do
    newrelic.record_metric('dns/query', 1)

    answers, err = resolvers[i][2]:query(qname, opts)

    ngx.log(ngx.DEBUG, 'resolver query: ', qname, ' nameserver: ', resolvers[i][1][1],':', resolvers[i][1][2])

    if answers and not answers.errcode and not err then
      break
    end
  end
  newrelic.end_segment(nr_transaction_id, dns_segment_id)

  return answers, err
end

return _M
