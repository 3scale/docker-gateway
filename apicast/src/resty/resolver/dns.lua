local resty_resolver = require 'resty.dns.resolver'
local newrelic = require 'resty.newrelic'

local setmetatable = setmetatable
local insert = table.insert
local traceback = debug.traceback
local concat = table.concat
local tostring = tostring
local format = string.format

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

local nameserver_mt = {
  __tostring = function(t)
    return concat(t, ':')
  end
}
function _M:init_resolvers()
  local resolvers = self.resolvers
  local nameservers = self.nameservers

  local nr_transaction_id = ngx.ctx.nr_transaction_id or ngx.var.nr_transaction_id
  local resolver_segment_id = nr_transaction_id and newrelic.begin_generic_segment(nr_transaction_id, newrelic.NEWRELIC_AUTOSCOPE, 'initialize resolver')

  for i=1,#nameservers do
    insert(resolvers, { setmetatable(nameservers[i], nameserver_mt), resty_resolver:new({ nameservers = { nameservers[i] }}) })
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

  local nr_transaction_id = ngx.ctx.nr_transaction_id or ngx.var.nr_transaction_id

  local resolver_segment_id = newrelic.begin_generic_segment(
    nr_transaction_id, newrelic.NEWRELIC_AUTOSCOPE, 'DNS/query')

  for i=1, #resolvers do
    local server = tostring(resolvers[i][1])
    newrelic.record_metric('dns/query', 1)

    local query_segment_id = newrelic.begin_datastore_segment(
      nr_transaction_id, newrelic.NEWRELIC_AUTOSCOPE, 'dns', newrelic.NEWRELIC_DATASTORE_SELECT, format("SELET `%s` FROM `%s`", qname, server))

    answers, err = resolvers[i][2]:query(qname, opts)

    newrelic.end_segment(nr_transaction_id, query_segment_id)

    ngx.log(ngx.DEBUG, 'resolver query: ', qname, ' nameserver: ', server)

    if answers and not answers.errcode and not err then
      break
    end
  end

  if err then
    newrelic.notice_transaction_error(nr_transaction_id, 'dns error', err, traceback(), "\n")
  end

  newrelic.end_segment(nr_transaction_id, resolver_segment_id)

  return answers, err
end

return _M
