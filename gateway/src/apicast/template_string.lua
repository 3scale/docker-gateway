local Liquid = require 'liquid'
local LiquidTemplate = Liquid.Template
local LiquidInterpreterContext = Liquid.InterpreterContext
local LiquidFilterSet = Liquid.FilterSet
local LiquidResourceLimit = Liquid.ResourceLimit
local ngx = ngx

local setmetatable = setmetatable
local pairs = pairs
local format = string.format

local LiquidTemplateString = {}
local liquid_template_string_mt = { __index = LiquidTemplateString }

-- Expose only ngx.* functions that we think could be useful and that do not
-- have any side-effects.

-- Table of ngx.* functions that we think can be useful for templates and do
-- not have any side-effects.
-- @field escape_uri https://github.com/openresty/lua-nginx-module#ngxescape_uri
-- @field unescape_uri https://github.com/openresty/lua-nginx-module#ngxunescape_uri
-- @field encode_base64 https://github.com/openresty/lua-nginx-module#ngxencode_base64
-- @field decode_base64 https://github.com/openresty/lua-nginx-module#ngxdecode_base64
-- @field crc32_short https://github.com/openresty/lua-nginx-module#ngxcrc32_short
-- @field crc32_long https://github.com/openresty/lua-nginx-module#ngxcrc32_long
-- @field hmac_sha1 https://github.com/openresty/lua-nginx-module#ngxhmac_sha1
-- @field md5 https://github.com/openresty/lua-nginx-module#ngxmd5
-- @field md5_bin https://github.com/openresty/lua-nginx-module#ngxmd5_bin
-- @field sha1_bin https://github.com/openresty/lua-nginx-module#ngxsha1_bin
-- @field quote_sql_str https://github.com/openresty/lua-nginx-module#ngxquote_sql_str
-- @field today https://github.com/openresty/lua-nginx-module#ngxtoday
-- @field time https://github.com/openresty/lua-nginx-module#ngxtime
-- @field now https://github.com/openresty/lua-nginx-module#ngxnow
-- @field localtime https://github.com/openresty/lua-nginx-module#ngxlocaltime
-- @field utctime https://github.com/openresty/lua-nginx-module#ngxutctime
-- @field cookie_time https://github.com/openresty/lua-nginx-module#ngxcookie_time
-- @field http_time https://github.com/openresty/lua-nginx-module#ngxhttp_time
-- @field parse_http_time https://github.com/openresty/lua-nginx-module#ngxparse_http_time
local liquid_filters = {
  escape_uri = ngx.escape_uri,
  unescape_uri = ngx.unescape_uri,
  encode_base64 = ngx.encode_base64,
  decode_base64 = ngx.decode_base64,
  crc32_short = ngx.crc32_short,
  crc32_long = ngx.crc32_long,
  hmac_sha1 = ngx.hmac_sha1,
  md5 = ngx.md5,
  md5_bin = ngx.md5_bin,
  sha1_bin = ngx.sha1_bin,
  quote_sql_str = ngx.quote_sql_str,
  today = ngx.today,
  time = ngx.time,
  now = ngx.now,
  localtime = ngx.localtime,
  utctime = ngx.utctime,
  cookie_time = ngx.cookie_time,
  http_time = ngx.http_time,
  parse_http_time = ngx.parse_http_time
}

local liquid_filter_set = LiquidFilterSet:new()
for name, func in pairs(liquid_filters) do
  liquid_filter_set:add_filter(name, func)
end

local liquid_resource_limit

function LiquidTemplateString.new(string)
  return setmetatable({ template = LiquidTemplate:parse(string) },
                      liquid_template_string_mt)
end

function LiquidTemplateString:render(context)
  return self.template:render(
    LiquidInterpreterContext:new(context),
    liquid_filter_set,
    liquid_resource_limit
  )
end

local PlainTemplateString = {}
local plain_template_string_mt = { __index = PlainTemplateString }

function PlainTemplateString.new(string)
  return setmetatable({ string = string }, plain_template_string_mt)
end

function PlainTemplateString:render()
  return self.string
end

local template = {
  plain = PlainTemplateString,
  liquid = LiquidTemplateString
}

local _M = {}

--- Initialize a template
-- Initialize a liquid or a plain text template according to the given type.
-- @tparam string value String to construct the template from
-- @tparam string type Render the template as this type.
--   Can be 'liquid' or 'plain'
-- @treturn a template string and nil, err when an invalid type is given
function _M.new(value, type, loopcount)
  local template_mod = template[type]
  liquid_resource_limit = LiquidResourceLimit:new(nil, nil, loopcount or 0)

  if template_mod then
    return template_mod.new(value)
  else
    return nil, format('Invalid type specified: %s', type)
  end
end

return _M
