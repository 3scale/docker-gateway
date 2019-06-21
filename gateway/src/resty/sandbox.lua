--- Sandbox
-- @module resty.sandbox
-- It uses sandboxed require to isolate dependencies and not mutate global state.
-- That allows for loading several versions of the same code with different dependencies.
-- And even loading several independent copies of the same code with no shared state.
-- Each object returned by the loader is new table and shares only shared code outside the defined load paths.

local format = string.format
local error = error
local type = type
local loadfile = loadfile
local insert = table.insert
local setmetatable = setmetatable
local concat = table.concat

local _G = _G
local _M = {
  -- Changing this to true enables very verbose debug logging of all requires in the sandbox.
  -- It is recommended to be enabled only in development time as it can easily overwhelm the log.
  debug = false,
}

local searchpath = package.searchpath
local root_loaded = package.loaded

local root_require = require

local preload = package.preload

local function debug_log(...)
  if _M.debug then
    ngx.log(ngx.DEBUG, ...)
  end
end

--- create a require function not using the global namespace
-- loading code from a namespace should have no effect on the global namespace
-- but that code can load shared libraries that would be cached globally
local function gen_require(package)

  local function not_found(modname, err)
    return error(format("module '%s' not found:%s", modname, err), 0)
  end

  --- helper function to safely use the native require function
  local function fallback(modname)
    local mod

    mod = package.loaded[modname]

    if not mod then
      debug_log('native require for: ', modname)
      mod = root_require(modname)
    end

    return mod
  end

  --- helper function to find and return correct loader for a module
  local function find_loader(modname)
    local loader, file, err, ret

    -- http://www.lua.org/manual/5.2/manual.html#pdf-package.searchers

    -- When looking for a module, require calls each of these searchers in ascending order,
    for i=1, #package.searchers do
      -- with the module name (the argument given to require) as its sole parameter.
      ret, err = package.searchers[i](modname)

      -- The function can return another function (the module loader)
      -- plus an extra value that will be passed to that loader,
      if type(ret) == 'function' then
        loader = ret
        file = err
        break
        -- or a string explaining why it did not find that module
      elseif type(ret) == 'string' then
        err = ret
      end
      -- (or nil if it has nothing to say).
    end

    return loader, file, err
  end

  --- reimplemented require function
  -- - return a module if it was already loaded (globally or locally)
  -- - try to find loader function
  -- - fallback to global require
  -- @tparam string modname module name
  -- @tparam boolean exclusive load only sandboxed code, turns off the fallback loader
  return function(modname, exclusive)
    -- http://www.lua.org/manual/5.2/manual.html#pdf-require
    debug_log('sandbox require: ', modname)

    -- The function starts by looking into the package.loaded table
    -- to determine whether modname is already loaded.
    -- NOTE: this is different from the spec: use the top level package.loaded,
    --       otherwise it would try to sandbox load already loaded shared code
    local mod = root_loaded[modname] or package.loaded[modname]

    --  If it is, then require returns the value stored at package.loaded[modname].
    if mod then return mod end

    -- Otherwise, it tries to find a loader for the module.
    local loader, file, err = find_loader(modname)

    -- Once a loader is found,
    if loader then
      debug_log('sandboxed require for: ', modname, ' file: ', file)
      -- require calls the loader with two arguments:
      --   modname and an extra value dependent on how it got the loader.
      -- (If the loader came from a file, this extra value is the file name.)
      mod = loader(modname, file)
    elseif not exclusive then
      debug_log('fallback loader for: ', modname, ' error: ', err)
      mod = fallback(modname)
    else
      -- If there is any error loading or running the module,
      -- or if it cannot find any loader for the module, then require raises an error.
      return not_found(modname, err)
    end

    -- If the loader returns any non-nil value,
    if mod ~= nil then
      -- require assigns the returned value to package.loaded[modname].
      package.loaded[modname] = mod

      -- If the loader does not return a non-nil value
      -- and has not assigned any value to package.loaded[modname],
    elseif not package.loaded[modname] then
      -- then require assigns true to this entry.
      package.loaded[modname] = true
    end

    -- In any case, require returns the final value of package.loaded[modname].
    return package.loaded[modname]
  end
end

local function export(list, env)
  assert(env, 'missing env')
  list:gsub('%S+', function(id)
    local module, method = id:match('([^%.]+)%.([^%.]+)')
    if module then
      env[module]         = env[module] or {}
      env[module][method] = _G[module][method]
    else
      env[id] = _G[id]
    end
  end)

  return env
end

--- this is environment exposed to the sandbox
-- that means this is very light sandbox so sandboxed code does not mutate global env
-- and most importantly we replace the require function with our own
-- The env intentionally does not expose getfenv so sandboxed code can't get top level globals.
-- And also does not expose functions for loading code from filesystem (loadfile, dofile).
-- Neither exposes debug functions unless openresty was compiled --with-debug.
-- But it exposes ngx as the same object, so it can be changed from within the sandbox.
_M.env = export([[
 _VERSION assert print xpcall pcall error
 unpack next ipairs pairs select
 collectgarbage gcinfo newproxy loadstring load
 setmetatable getmetatable
 tonumber tostring type
 rawget rawequal rawlen rawset

 bit.arshift bit.band bit.bnot bit.bor bit.bswap bit.bxor
 bit.lshift bit.rol bit.ror bit.rshift bit.tobit bit.tohex

 coroutine.create coroutine.resume coroutine.running coroutine.status
 coroutine.wrap   coroutine.yield coroutine.isyieldable

 debug.traceback

 io.open io.close io.flush io.tmpfile io.type
 io.input io.output io.stderr io.stdin io.stdout
 io.popen io.read io.lines io.write

 math.abs math.acos math.asin math.atan math.atan2
 math.ceil math.cos math.cosh math.deg math.exp math.floor
 math.fmod math.frexp math.ldexp math.log math.pi
 math.log10 math.max math.min math.modf math.pow
 math.rad math.random math.randomseed math.huge
 math.sin math.sinh math.sqrt math.tan math.tanh

 os.clock os.date os.time os.difftime
 os.execute os.getenv
 os.rename os.tmpname os.remove

 string.byte string.char string.dump string.find
 string.format string.lower string.upper string.len
 string.gmatch string.match string.gsub string.sub
 string.rep string.reverse

 table.concat table.foreach table.foreachi table.getn
 table.insert table.maxn table.move table.pack
 table.remove table.sort table.unpack

 ngx arg
]], {})

_M.env._G = _M.env

-- add debug functions only when nginx was compiled --with-debug
if ngx.config.debug then
  _M.env = export([[ debug.debug debug.getfenv debug.gethook debug.getinfo
      debug.getlocal debug.getmetatable debug.getregistry
      debug.getupvalue debug.getuservalue debug.setfenv
      debug.sethook debug.setlocal debug.setmetatable
      debug.setupvalue debug.setuservalue debug.upvalueid debug.upvaluejoin
  ]], _M.env)
end

local mt = {
  __call = function(loader, ...) return loader.env.require(...) end
}

local empty_t = {}

function _M.new(load_paths, cache)
  -- need to create global variable package that mimics the native one
  local package = {
    loaded = cache or {},
    preload = preload,
    searchers = {}, -- http://www.lua.org/manual/5.2/manual.html#pdf-package.searchers
    searchpath = searchpath,
    path = concat(load_paths or empty_t, ';'),
    cpath = '', -- no C libraries allowed in sandbox
  }

  -- creating new env for each sadnbox means they can't accidentaly share global variables
  local env = setmetatable({
    require = gen_require(package),
    package = package,
  }, { __index = _M.env })

  -- The first searcher simply looks for a loader in the package.preload table.
  insert(package.searchers, function(modname) return package.preload[modname] end)
  -- The second searcher looks for a loader as a Lua library, using the path stored at package.path.
  -- The search is done as described in function package.searchpath.
  insert(package.searchers, function(modname)
    local file, err = searchpath(modname, package.path)
    local loader

    if file then
      loader, err = loadfile(file, 'bt', env)

      debug_log('loading file: ', file)

      if loader then return loader, file end
    end

    return err
  end)

  local self = {
    env = env
  }

  return setmetatable(self, mt)
end

return _M
