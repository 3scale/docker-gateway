local co_create = coroutine._create
local co_resume = coroutine._resume

local _M = {}

--- Create coroutine iterator
-- Like coroutine.wrap but safe to be used as iterator,
-- because it will return nil as first return value on error.
function _M.co_wrap_iter(f)
  local co = co_create(f)

  return function(...)
    local ok, ret = co_resume(co, ...)

    if ok then
      return ret
    else
      return nil, ret
    end
  end
end

return _M

