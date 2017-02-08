local resty_lrucache = require "resty.lrucache"
local inspect = require 'inspect'

local setmetatable = setmetatable
local ipairs = ipairs
local pairs = pairs
local min = math.min
local insert = table.insert
local concat = table.concat

local co_yield = coroutine.yield
local co_create = coroutine.create
local co_resume = coroutine.resume

local lrucache = resty_lrucache.new(1000)

local _M = {
  _VERSION = '0.1'
}

local mt = { __index = _M }

function _M.new(cache)
  return setmetatable({
    cache = cache or lrucache
  }, mt)
end

local function compact_answers(servers)
  local hash = {}
  local compact = {}

  for i=1, #servers do
    local server = servers[i]
    local name = server.name or server.address

    local packed = hash[name]

    if packed then
      insert(packed, server)
      packed.ttl = min(packed.ttl, server.ttl)
    else
      packed = {
        server,
        name = name,
        ttl = server.ttl
      }

      insert(compact, packed)
      hash[name] = packed
    end
  end

  return compact
end

function _M.store(self, answer)
  local cache = self.cache

  if not cache then
    return nil, 'not initialized'
  end

  local name = answer.name

  if not name then
    ngx.log(ngx.WARN, 'resolver cache write refused invalid answer ', inspect(answer))
    return nil, 'invalid answer'
  end

  ngx.log(ngx.DEBUG, 'resolver cache write ', name, ' with TLL ', answer.ttl)

  local ttl = answer.ttl

  if ttl == -1 then
    ttl = nil
  end

  return cache:set(name, answer, ttl)
end


function _M.save(self, answers)
  local ans = compact_answers(answers or {})

  for _, answer in pairs(ans) do
    local _, err = self:store(answer)

    if err then
      return nil, err
    end
  end

  return ans
end

local function fetch_answers(hostname, cache, stale, circular_reference)
  if not hostname then
    return {}, 'missing name'
  end

  if circular_reference[hostname] then
    error('circular reference detected when querying '.. hostname)
    return
  else
    circular_reference[hostname] = true
  end

  local answers, stale_answers = cache:get(hostname)

  if not answers then
    if stale and stale_answers then
      return stale_answers
    else
      return {}
    end
  end

  ngx.log(ngx.DEBUG, 'resolver cache read ', hostname, ' ', #answers, ' entries')

  return answers
end

local function yieldfetch(found, hostname, cache, stale, circular_reference)
  local answers = fetch_answers(hostname, cache, stale, circular_reference)
  local ret = found or {}

  for i=1, #answers do
    yieldfetch(ret, answers[i].cname, cache, stale, circular_reference)
    insert(ret, answers[i])
  end

  return ret
end

local function fetch(cache, name, stale)
  local circular_reference = {}

  return yieldfetch(nil, name, cache, stale, circular_reference)
end

local answers_mt = {
  __tostring = function(t)
    return concat(t.addresses, ', ')
  end
}

function _M.get(self, name)
  local cache = self.cache

  if not cache then
    return nil, 'not initialized'
  end

  local answers = setmetatable({ addresses = {} }, answers_mt)
  local records = fetch(cache, name)

  for i=1, #records do
    insert(answers, records[i])
    insert(answers.addresses, records[i].address)
  end

  if #records == 0 then
    ngx.log(ngx.DEBUG, 'resolver cache miss: ', name)
  else
    ngx.log(ngx.DEBUG, 'resolver cache hit: ', name, ' ', answers)
  end

  return answers
end

return _M
