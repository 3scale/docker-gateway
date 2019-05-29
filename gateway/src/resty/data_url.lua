--- Data URL Configuration Loader
-- This configuration loader parses and URL and exctracts the whole configuration JSON from it.
-- The URL has to be a Data URL with urlencoded or base64 encoding.
-- https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/Data_URIs
local _M = {}

local MimeType = require('resty.mime')

local pattern = [[^
data:
  (?<mediatype>[a-z]+\/[a-z0-9-+.]+)?
  (?:;
    (?:([a-z-]+=[^,;]+)|(?<base64>base64))
  )* # any number of parameters (name=value)
  ,
  (?<data>[a-zA-Z0-9!$&',()*+;=\-._~:@\/?%\s]*?)
$]]
local re_match = ngx.re.match

local function parse(url)
  local match, err = re_match(url, pattern, 'ojix')

  if not match then
    return nil, err or 'not valid data-url'
  end

  local data
  local opaque = match.data
  local base64 = not not match.base64

  if base64 then
    data = ngx.decode_base64(opaque)
  else
    data = ngx.unescape_uri(opaque)
  end

  return {
    mime_type = MimeType.new(match.mediatype),
    data = data,
    base64 = base64,
    -- opaque = opaque,
  }
end

_M.parse = parse

return _M
