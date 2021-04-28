local _M = require('apicast.policy').new('GC', 'builtin')


-- This policy allows APICast to remove data that it's staled from shared
-- dictionaries.  By default, Openresty only deletes this when trying to
-- write a new entry in the shared dict.  When no new requests in this
-- instance, will keep allocated the memory forever.

-- The main reason for this change was a user using blue-green deployment,
-- where the proxy is not receiving more traffic. However, the shared
-- dictionaries are full, so the data is still allocated and cannot be used
-- by other processes.


local mt = {
  __index = _M
}

--- When is not set, we set the cleanup each 300 seconds
local default_delay_cleanup = 300

--- This is called when APIcast boots the master process.
function _M.new(delay)
  local self = setmetatable({}, mt)
  self.delay = tonumber(delay) or default_delay_cleanup
  return self
end

-- Need to happens by worker, cannot run something like this on master process,
-- so need to run on each worker.
-- @TODO: This is so sad in Openresty, we need to find a way to detect a leader
-- in some way.
function _M:init_worker()
  local handler = function()
    for name,dict in pairs(ngx.shared) do
      local flushed = dict:flush_expired()
      ngx.log(ngx.DEBUG, "flushed ", flushed , " expired entries on shared dict '", name,"'")
    end
  end
  ngx.log(ngx.INFO, "GC cleanup process called every ", self.delay, "seconds")
  ngx.timer.every(self.delay, handler)
end

return _M
