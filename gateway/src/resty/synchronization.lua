--- resty.synchronization
-- module to de-duplicate work
-- @classmod resty.synchronization

local semaphore = require "ngx.semaphore"
local safe_task = require('resty.concurrent.safe_task_executor')

local rawset = rawset
local setmetatable = setmetatable

local _M = {
  _VERSION = '0.1'
}
local mt = {
  __index = _M
}
--- initialize new synchronization table
-- @tparam int size how many resources for each key
function _M.new(size)
  local semaphore_mt = {
    __index = function(t, k)
      local sema = semaphore.new(size or 1)
      sema.name = k
      rawset(t, k, sema)
      return sema
    end
  }

  local semaphores = setmetatable({}, semaphore_mt)
  return setmetatable({ semaphores = semaphores }, mt)
end

--- get semaphore for given key
-- @tparam string key key for the semaphore
-- @treturn resty.semaphore semaphore instance
-- @treturn string key
function _M:acquire(key)
  local semaphores = self.semaphores
  if not semaphores then
    return nil, 'not initialized'
  end
  return semaphores[key], key
end

--- release semaphore
-- to clean up unused semaphores
-- @tparam string key key for the semaphore
function _M:release(key)
  local semaphores = self.semaphores
  if not semaphores then
    return nil, 'not initialized'
  end
  semaphores[key] = nil
end

--- run a new function, callback using locks on the given key
-- @tparam string key: key for the semaphore
-- @tparam int timeout: timeout for getting the lock before raise an error.
-- @tparam function callback: function to execute if the lock is acquired correctly
-- @param ...: the variable number of arguments that are going to be send to the callback function.
function _M:run(key, timeout, callback, ...)
  local sema, err = self:acquire(key)
  if err ~= key then
    ngx.log(ngx.WARN, 'failed to acquire lock on key: ', key, ' error: ', err)
    return false
  end

  local lock_acquired, acquire_err = sema:wait(timeout)
  if not lock_acquired then
    ngx.log(ngx.WARN, 'failed to acquire lock on key: ', key, ' error: ', acquire_err)
    return false
  end

  local task = safe_task.new(callback)
  local ret, result, execute_error = task:execute(...)

  if lock_acquired then
    self.release(key)
    sema:post()
  end

  return ret, result, execute_error
end

return _M
