local pcall = pcall
local require = require
local dofile = dofile
local type = type

local env = require 'resty.env'

local prequire = function(file)
  local ok, ret = pcall(require, file)

  if not ok and ret then
    -- dofile can load absolue paths, require can't
    ok, ret = pcall(dofile, file)
  end

  if type(ret) == 'userdata' then
    ngx.log(ngx.WARN, 'cyclic require detected: ', debug.traceback())
    return false, ret
  end

  return ok, ret
end

local name = env.get('APICAST_MODULE') or 'apicast'

local ok, mod = prequire(name)

if ok and mod then
  if mod.new then
    return mod.new()
  else
    return mod
  end
else
  return ok, mod
end
