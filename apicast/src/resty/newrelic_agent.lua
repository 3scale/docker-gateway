--- module setup
local _M = { _VERSION = '0.01' }
package.loaded[...] = _M -- avoid returning module at the end of file

local newrelic = require 'resty.newrelic'

local license_key = os.getenv 'NEWRELIC_APP_LICENSE_KEY'
local app_name = os.getenv 'NEWRELIC_APP_NAME'

_M.enabled = ('string' == type(license_key) and 40 == #license_key)

_M.enable = function()
  if _M.enabled then
    newrelic.embed_collector()
    newrelic.init(license_key, app_name, 'lua', '-')
    ngx.log(ngx.ERR, 'Starting newrelic agent.')
  else
    ngx.log(ngx.ERR, 'Newrelic agent is not configured')
  end
end

_M.notice_error = function(...)
  if _M.enabled then
    newrelic.notice_transaction_error(ngx.ctx.nr_transaction_id, unpack({...}))
  end
end

_M.start_web_transaction = function()
  if _M.enabled then
    ngx.ctx.nr_transaction_id = newrelic.begin_transaction()
    newrelic.set_transaction_name(ngx.ctx.nr_transaction_id, ngx.var.uri)
  end
end

_M.finish_web_transaction = function()
  local transaction_id = ngx.ctx.nr_transaction_id

  if _M.enabled and transaction_id then
    newrelic.end_transaction(transaction_id)
  end
end

local make_wrapper = function(redis_client, method_name)
  return function(...)
    local parent_segment_id = ngx.ctx.nr_transaction_id
    local segment_id = newrelic.begin_datastore_segment(parent_segment_id, 0, 'redis', method_name)

    local result, err = redis_client[method_name](...)

    newrelic.end_segment(parent_segment_id, segment_id)

    return result, err
  end
end

_M.wrap_redis_client = function(redis_client)
  return setmetatable({}, { __index = function(wrapper_object, key)
    local original_value = redis_client[key]

    if _M.enabled and 'function' == type(original_value) then
      local wrapped_function = make_wrapper(redis_client, key)
      wrapper_object[key] = wrapped_function
      return wrapped_function
    else
      return original_value
    end
  end})
end
