local _M = {
  VERSION = '0.0.1'
}

local ngx_now = ngx.now

local len = string.len

local open = io.open
local execute = os.execute
local tmpname = os.tmpname
local unpack = unpack

function _M.timer(name, fun, ...)
  local start = ngx_now()
  ngx.log(ngx.INFO, 'benchmark start ' .. name .. ' at ' .. start)
  local ret = { fun(...) }
  local time = ngx_now() - start
  ngx.log(ngx.INFO, 'benchmark ' .. name .. ' took ' .. time)
  return unpack(ret)
end

local function read(file)
  local handle, err = open(file)
  local output

  if handle then
    output = handle:read("*a")
    handle:close()
  else
    return nil, err
  end

  return output
end

function _M.system(command)
  local tmpout = tmpname()
  local tmperr = tmpname()
  ngx.log(ngx.DEBUG, 'os execute ', command)

  local success, exit, code = execute('(' .. command .. ')' .. ' > ' .. tmpout .. ' 2> ' .. tmperr)
  local err

  tmpout, err = read(tmpout)

  if err then
    return nil, err
  end

  tmperr, err = read(tmperr)

  if err then
    return nil, err
  end

  -- os.execute returns exit code as first return value on OSX
  -- even though the documentation says otherwise (true/false)
  if success == 0 or success == true then
    if len(tmperr) then
      ngx.log(ngx.WARN, 'os execute stderr: \n', tmperr)
    end

    return tmpout
  else
    return tmpout, tmperr, code or exit or success
  end
end

return _M
