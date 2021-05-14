local pairs = pairs
local type = type
local assert = assert
local setmetatable = setmetatable
local getmetatable = getmetatable
local insert = table.insert
local remove = table.remove
local error = error
local format = string.format
local response = require 'resty.http_ng.response'

local _M = {}

local function contains(expected, actual)
  if actual == expected then return true end
  local t1,t2 = type(actual), type(expected)
  if t1 ~= t2 then
    local mt = getmetatable(actual) or {}
    if t2 == 'string' and mt.__tostring then
      return mt.__tostring(actual) == expected
    else
      return false, format("can't compare %q with %q", t1, t2)
    end
  end

  if t1 == 'table' then
    for k,v in pairs(expected) do
      local ok, err = contains(v, actual[k])
      if not ok then
        return false, format('[%q] %s', k, err)
      end
    end
    return true
  end

  return false, format('%q does not match %q', actual, expected)
end


_M.expectation = {}

_M.expectation.new = function(request)
  assert(request, 'needs expected request')
  local expectation = { request = request }

  -- chain function to add a response to expectation
  local mt = {
    respond_with = function(res)
      expectation.response = res
    end
   }

  return setmetatable(expectation, {__index = mt})
end

_M.expectation.match = function(expectation, request)
  return contains(expectation.request, request)
end

local missing_expectation_mt = {
  __tostring = function(t)
    local str = [[
Missing expecation to match request. Try following:
test_backend.expect{ url = %q }.
  respond_with{ status = 200, body = "" }
    ]]
    return format(str, t.request.url)
  end
}

local function missing_expecation(request)
  local exception = { request = request }

  return setmetatable(exception, missing_expectation_mt)
end

_M.missing_expectation = missing_expecation

_M.new = function()
  local requests = {}
  local expectations = {}
  local backend = {}

  backend.expect = function(request)
    local expectation = _M.expectation.new(request)
    insert(expectations, expectation)
    return expectation
  end

  backend.send = function(_, request)
    local expectation = remove(expectations, 1)

    if not expectation then error(missing_expecation(request)) end
    local match, err = _M.expectation.match(expectation, request)
    if not match then error('expectation does not match: ' .. err) end

    insert(requests, request)

    local res = expectation.response

    return response.new(request, res.status, res.headers, res.body or '')
  end

  backend.verify_no_outstanding_expectations = function()
    assert(#expectations == 0, 'has ' .. #expectations .. ' outstanding expectations')
  end

  backend.get_requests = function()
    return  requests
  end

  return backend
end

return _M
