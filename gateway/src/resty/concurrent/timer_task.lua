local GC = require 'apicast.gc'

local uuid = require 'resty.jit-uuid'
local unpack = unpack

local _M = {}

local default_interval_seconds = 60

_M.active_tasks = {}

function _M.register_task(id)
  _M.active_tasks[id] = true
end

function _M.unregister_task(id)
  _M.active_tasks[id] = nil
end

function _M.task_is_active(id)
  return _M.active_tasks[id] or false
end

local function generate_id()
  return uuid.generate_v4()
end

local function gc(self)
  _M.unregister_task(self.id)
end

local mt = {
  __gc = gc,
  __index = _M
}

--- Initialize a TimerTask.
-- @tparam function task The function to be run periodically
-- @tparam[opt] table opts
-- @tfield ?table args Arguments to the function
-- @tfield ?number interval Interval in seconds (defaults to 60)
function _M.new(task, opts)
  local options = opts or {}

  local id = generate_id()

  local self = GC.set_metatable_gc({}, mt)
  self.task = task
  self.args = options.args
  self.interval = options.interval or default_interval_seconds
  self.id = id

  _M.register_task(id)

  return self
end

local run_periodic, schedule_next, timer_execute

run_periodic = function(self, run_now)
  if not _M.task_is_active(self.id) then return end

  if run_now then
    self.task(unpack(self.args))
  end

  schedule_next(self)
end

-- Note: ngx.timer.at always sends "premature" as the first param.
-- "premature" is boolean value indicating whether it is a premature timer
-- expiration.
timer_execute = function(_, self)
  run_periodic(self, true)
end

schedule_next = function(self)
  local ok, err = ngx.timer.at(self.interval, timer_execute, self)

  if not ok then
    ngx.log(ngx.ERR, "failed to schedule timer task: ", err)
  end
end

--- Execute a task
-- @tparam[opt] run_now boolean True to run the task immediately or False to
--   wait 'interval' seconds. (Defaults to false)
function _M:execute(run_now)
  run_periodic(self, run_now or false)
end

function _M:cancel()
  _M.unregister_task(self.id)
end

return _M
