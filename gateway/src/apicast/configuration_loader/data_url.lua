--- Data URL Configuration Loader
-- This configuration loader parses and URL and exctracts the whole configuration JSON from it.
-- The URL has to be a Data URL with urlencoded or base64 encoding.
-- https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/Data_URIs
local _M = {}

local MimeType = require('resty.mime')
local cjson = require('cjson')
local YAML = require('resty.yaml')

local pattern = [[^data:(?<mediatype>[a-z]+\/[a-z0-9-+.]+(?<charset>;[a-z-]+=[a-z0-9-]+)?)?(?<base64>;base64)?,(?<data>[a-z0-9!$&',()*+;=\-._~:@\/?%\s]*?)$]]
local re_match = ngx.re.match

local function parse(url)
  local match, err = re_match(url, pattern, 'oji')

  if match then

    return {
      mime_type = MimeType.new(match.mediatype),
      data = match.data,
      base64 = not not match.base64,
    }
  else
    return nil, err or 'not valid data-url'
  end
end

local decoders = {
  ['application/json'] = function(data) return cjson.decode(data) end,
  ['application/yaml'] = function(data) return YAML.load(data) end,
}

local function decode(data_url)

  local data = data_url.data

  if data_url.base64 then
    data = ngx.decode_base64(data)
  else
    data = ngx.unescape_uri(data)
  end

  local media_type = data_url.mime_type.media_type

  local decoder = decoders[media_type]

  if decoder then
    return decoder(data)
  else
    return nil, 'unsupported mediatype'
  end
end

function _M.parse(uri)
  local data_url, err = parse(uri)

  if not data_url then return nil, err end

  return decode(data_url)
end

function _M.call(uri)
  local data, err = _M.parse(uri)

  if err then return nil, err end

  return cjson.encode(data)
end


return _M
