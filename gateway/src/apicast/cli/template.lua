local _M = {}

local setmetatable = setmetatable
local insert = table.insert
local assert = assert
local pairs = pairs
local ipairs = ipairs
local sub = string.sub
local len = string.len
local pack = table.pack
local fs = require('apicast.cli.filesystem')
local pl = { dir = require('pl.dir'), path = require('pl.path'), file = require('pl.file') }
local Liquid = require 'liquid'
local resty_env = require('resty.env')
local Lexer = Liquid.Lexer
local Parser = Liquid.Parser
local Interpreter = Liquid.Interpreter
local FilterSet = Liquid.FilterSet
local InterpreterContext = Liquid.InterpreterContext
local FileSystem = Liquid.FileSystem
local ResourceLimit = Liquid.ResourceLimit

local function noop(...) return ... end


function _M:new(config, dir, strict)
    local instance = setmetatable({}, { __index = self })
    local env = {}

    for name,value in pairs(resty_env.list()) do
        insert(env, { name = name, value = value })
        env[name] = value
    end

    local context = setmetatable({
        env = env,
        platform = jit.os,
    }, { __index = config })

    instance.root = pl.path.abspath(dir or pl.path.currentdir())
    instance.context = InterpreterContext:new(context)
    instance.strict = strict
    instance.filesystem = FileSystem:new(function(path)
        return instance:read(path)
    end)

    return instance
end

function _M:read(template_name)
    local root = self.root
    local check = self.strict and assert or noop

    assert(template_name, 'missing template name')
    return check(pl.file.read(pl.path.join(root, template_name)))
end

function _M:render(template_name)
    local template = self:read(template_name)
    return self:interpret(template)
end

local function starts_with(string, match)
    return sub(string,1,len(match)) == match
end

local function build_interpreter(str)
    local lexer = Lexer:new(str)
    local parser = Parser:new(lexer)
    local interpreter = Interpreter:new(parser)

    return interpreter
end

local function nginx_prefix()
    local match = ngx.re.match(ngx.config.nginx_configure(), [[--prefix=(.+?)\s]])
    if match then return match[1] end
end

local function dirtree(dir, cache)
  local cached = cache[dir]

  if cached then
    return pairs(cached)
  else
    cache[dir] = {}
    return fs(dir)
  end
end

function _M:interpret(str)
    local interpreter = build_interpreter(str)

    local context = self.context
    local filesystem = self.filesystem
    local filter_set = FilterSet:new()
    local resource_limit = ResourceLimit:new(nil, 1000, nil)

    local filesystem_cache = {}

    filter_set:add_filter('filesystem', function(pattern)
        local files = {}
        local included = {}

        for _, root in ipairs({ self.root, pl.path.currentdir(), ngx.config.prefix(), nginx_prefix() }) do
            for filename in dirtree(root, filesystem_cache) do
                local file = pl.path.relpath(filename, root)

                if pl.dir.fnmatch(file, pattern) and not included[filename] and not included[file] then
                    insert(files, filename)
                    included[filename] = true
                    included[file] = true
                end

                filesystem_cache[root][filename] = true
            end
        end

        return files
    end)

    filter_set:add_filter('default', function(value, default)
        if value == nil then return default else return value end
    end)

    filter_set:add_filter('starts_with', function(string, ...)
        local matches = pack(...)
        for i=1, matches.n do
            if starts_with(string, matches[i]) then return true end
        end
    end)

    filter_set:add_filter('tostring', function(string)
      return tostring(string)
    end)

    return interpreter:interpret(context, filter_set, resource_limit, filesystem)
end

return _M
