local now = ngx.now

local counter = require "resty.counter"
local countdown_counter =  require("apicast.policy.rate_limit_headers.countdown_counter")
local stringx = require 'pl.stringx'

local _M = {}
local mt = { __index = _M }

local export_separator = "#"

function _M.new(usage, max, remaining, reset)
  local self = setmetatable({}, mt)

  self.usage = usage
  self:reset(max, remaining, reset)

  return self
end

function _M.Init_empty(usage)
  local self = setmetatable({}, mt)

  self.usage = usage
  self:reset(0, 0, now())
  return self
end

function _M:decrement(delta)
    self.remaining:decrement(delta)
end

function _M:dump_data()
    return {
        limit = self.limit:__tostring(),
        remaining = self.remaining:__tostring(),
        reset = self.reset:remaining_secs_positive(now()),
    }
end

function _M:reset(max, remaining, reset)
  self.limit = counter.new(max)
  self.remaining = counter.new(remaining)
  self.reset = countdown_counter.new(reset, now())
end

function _M:export()
  return string.format("%s%s%s%s%s",
    self.limit:__tostring(), export_separator,
    self.remaining:__tostring(), export_separator,
    self.reset:remaining_secs_positive(now()))
end

function _M.import(usage, exported_data)
  if not usage then
    return nil
  end

  if not exported_data then
    return _M.Init_empty(usage)
  end

  local data = stringx.split(exported_data, export_separator)
  return _M.new(usage, data[1] or 0, data[2] or 0, data[3] or 0)
end


return _M
