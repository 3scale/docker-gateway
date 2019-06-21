local resty_url = require('resty.url')

local setmetatable = setmetatable

local _M = {

}
local mt = { __index = _M }

local allowed_schemes = {
    file = true,
    data = true,
}


function _M.new(uri)
    local url, err = resty_url.parse(uri)

    if not url then return nil, err end

    if not allowed_schemes[url.scheme] then
        return nil, 'scheme not supported'
    end

    return setmetatable({ url = url }, mt)
end

do
    local loaders = { }
    local pcall = pcall
    local tostring = tostring
    local path = require('pl.path')
    local file = require('pl.file')
    local inspect = require('inspect')
    local tab_clone = require "table.clone"
    local __tostring = function(self)
        -- We need to remove metatable of the inspected table, otherwise it points to itself
        -- and leads to infinite recursion. Cloning the table has the same effect without mutation.
        -- As this is evaluated only when nginx was compiled with debug flag,
        -- it means it happens only in development.
        return inspect(tab_clone(self))
    end

    local config_mt = { __tostring = __tostring }

    local YAML = require('resty.yaml')
    local cjson = require('cjson')
    local data_url = require('apicast.configuration_loader.data_url')

    local decoders = {
        ['.yml'] = YAML.load,
        ['.yaml'] = YAML.load,
        ['.json'] = cjson.decode,
    }

    local function decode(fmt, contents)
        local decoder = decoders[fmt]

        if not decoder then return nil, 'unsupported format' end

        local ok, ret = pcall(decoder, contents)

        if ok then
            return ret
        else
            return false, ret
        end
    end

    function loaders.file(uri)
        local filename = uri.opaque or ('%s%s'):format(uri.host, uri.path)
        if not filename then return nil, 'invalid file url' end

        local ext = path.extension(filename)
        local contents = file.read(filename)

        if contents then
            return decode(ext, contents)
        else
            return nil, 'no such file'
        end
    end

    function loaders.data(uri)
        return data_url.parse(tostring(uri))
    end

    function _M:load()
        local url = self and self.url
        if not url then return nil, 'not initialized' end

        local load = loaders[url.scheme]
        if not load then return nil, 'cannot load scheme' end

        local t, err = load(url)

        if t then
            return setmetatable(t, config_mt)
        else
            return t, err
        end
    end
end

return _M
