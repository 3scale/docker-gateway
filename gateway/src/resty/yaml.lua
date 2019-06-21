local yaml = require('lyaml.functional')

yaml.NULL = ngx.null
yaml.isnull = function(value) return value == ngx.null end

local YAML = require('lyaml')

local _M = {
  load = YAML.load,
  null = YAML.null,
}

return _M
