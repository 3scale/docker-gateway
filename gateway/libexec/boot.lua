-- Clean warning on openresty 1.15.8.1, where some global variables are set,
-- and a warning message is show during startup outside apicast packages.
-- Code related: https://github.com/openresty/lua-nginx-module/blob/61e4d0aac8974b8fad1b5b93d0d3d694d257d328/src/ngx_http_lua_util.c#L795-L839
(getmetatable(_G) or {}).__newindex = nil

package.path = package.path .. ";./src/?.lua;"
require('apicast.loader')

local configuration = require 'apicast.configuration_loader'
local config = configuration.boot()

ngx.say(config)
