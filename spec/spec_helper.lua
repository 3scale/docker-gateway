require 'ffi'
require 'resty.lrucache'
require 'resty.aes'
require 'resty.hmac'

require 'ngx_helper'
require 'luassert_helper'
require 'jwt_helper'

require('resty.limit.req') -- because it uses ffi.cdef and can't be reloaded

local busted = require('busted')
local env = require('resty.env')

local previous_env = {}
local set = env.set
local null = {'null'}

-- override resty.env.set with custom function that remembers previous values
env.set = function(name, ...)
  local previous = set(name, ...)

  if not previous_env[name] then
    previous_env[name] = previous or null
  end

  return previous
end

-- so they can be reset back to the values before the test run
local function reset()
  for name, value in pairs(previous_env) do
    if value == null then
      value = nil
    end
    set(name, value)
  end

  previous_env = {}

  env.reset()

  -- To make sure that we are using valid policy configs in the tests.
  set('APICAST_VALIDATE_POLICY_CONFIGS', true)
end

busted.before_each(reset)
busted.after_each(reset)

busted.subscribe({ 'file', 'start' }, function (attr)
  require('apicast.loader')
end)

busted.subscribe({ 'file', 'end' }, function (attr)
  collectgarbage()
end)