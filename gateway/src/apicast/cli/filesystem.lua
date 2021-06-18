--- Filesystem for CLI
-- This module exposes functions that work with filesystem.
-- So far exposes only function - to recursively traverse a filesystem path.
-- Workaround for https://github.com/stevedonovan/Penlight/issues/265
--

--- These lines to avoid _G write guard issues, external depencies
--  See https://github.com/openresty/lua-nginx-module/issues/1558 for more info
rawset(_G, 'lfs', false)
rawset(_G, 'warn', false)

local pl_path = require('pl.path')
local exists, isdir = pl_path.exists, pl_path.isdir
local pl_path_dir = pl_path.dir
local pl_path_join = pl_path.join
local abspath = pl_path.abspath
local pcall = pcall
local co_yield = coroutine.yield
local co_create = coroutine.create
local co_resume = coroutine.resume

local noop = function () end

--- Safely try to get directory iterator
local function ldir(dir)
  local ok, iter, state = pcall(pl_path_dir, dir)

  if ok then
    return iter, state
  else
    ngx.log(ngx.DEBUG, 'error listing directory: ', dir, ' err: ', iter)
    return noop
  end
end

--- Create coroutine iterator
-- Like coroutine.wrap but safe to be used as iterator,
-- because it will return nil as first return value on error.
local function co_wrap_iter(f)
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

--- Recursively list directory
-- This is a copy of penlight's dir.dirtree
return function ( d )
  if not d then return nil end

  local function yieldtree( dir )
    for entry in ldir( dir ) do
      if entry ~= '.' and entry ~= '..' then
        entry = pl_path_join(dir, entry)

        if exists(entry) then  -- Just in case a symlink is broken.
          local is_dir = isdir(entry)
          co_yield( entry, is_dir )
          if is_dir then
            yieldtree( entry )
          end
        end
      end
    end
  end

  return co_wrap_iter(function() yieldtree( abspath(d) ) end)
end
