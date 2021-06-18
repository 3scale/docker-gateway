local init = false
local _M = {}

local function init_yaml()
  if not  init then
    init = true
    yaml = require('lyaml.functional')
    yaml.NULL = ngx.null
    yaml.isnull = function(value) return value == ngx.null end
    YAML = require('lyaml')
    _M["load"] = YAML.load
    _M["null"] = YAML.null
  end
end


local mt = {
  __index = function (self, key)
    init_yaml()
    return _M[key]
  end
}

return setmetatable({}, mt)
