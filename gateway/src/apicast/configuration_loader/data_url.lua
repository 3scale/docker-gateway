--- Data URL Configuration Loader
-- This configuration loader parses and URL and exctracts the whole configuration JSON from it.
-- The URL has to be a Data URL with urlencoded or base64 encoding.
-- https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/Data_URIs
local _M = {}

local data_url = require('resty.data_url')
local cjson = require('cjson')
local YAML = require('resty.yaml')

local parse = data_url.parse

local decoders = {
  ['application/json'] = function(data) return cjson.decode(data) end,
  ['application/yaml'] = function(data) return YAML.load(data) end,
}

local function decode(res)
  local data = res.data
  local media_type = res.mime_type.media_type

  local decoder = decoders[media_type]

  if decoder then
    return decoder(data)
  else
    return nil, 'unsupported mediatype'
  end
end

function _M.parse(uri)
  local res, err = parse(uri)

  if not res then return nil, err end

  return decode(res)
end

function _M.call(uri)
  local data, err = _M.parse(uri)

  if err then return nil, err end

  return cjson.encode(data)
end


return _M
