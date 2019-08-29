local format = string.format
local lower = string.lower
local setmetatable = setmetatable

local re = require('ngx.re')
local re_match = ngx.re.match
local re_split = re.split

local _M = {}
local MimeType_mt = { __index = _M }


function _M.new(media_type)
  if not media_type then
    return setmetatable({}, MimeType_mt)
  end

  -- The [RFC[(https://tools.ietf.org/html/rfc7231#section-3.1.1.1) defines

  -- that space around `;` is irrelevant, so remove it when splitting
  local match = re_split(media_type, [[\s*;\s*]], 'oj', nil, 2)

  local self = {}

  -- that the type can include upper and lower-case chars.
  -- Let's convert it to lower-case for easier comparisons.
  self.media_type = lower(match[1])
  self.parameters = match[2]

  return setmetatable(self, MimeType_mt)
end

-- to be interpolated by string.format with the parameter name
-- extracts either quoted string till next quote or
-- a string without quotes till next parameter or end of the string
local parameter_pattern = [[%s=(?:"(.+?)"|([^\s;"]+))\s*(?:;|$)]]

function _M:parameter(name)
  local parameters = self.parameters

  local matches = re_match(parameters, format(parameter_pattern, name), 'oji')

  if not matches then return nil end

  return matches[1] or matches[2]
end

return _M
