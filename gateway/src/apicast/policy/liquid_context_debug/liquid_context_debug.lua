local context_content = require('context_content')
local cjson = require('cjson')
local policy = require('apicast.policy')
local ngx_variable = require('apicast.policy.ngx_variable')
local _M = policy.new('Liquid context debug', 'builtin')

local new = _M.new

function _M.new(config)
  local self = new(config)
  return self
end

function _M.content(_, context)
  local liquid_context = ngx_variable.available_context(context)
  local content = context_content.from(liquid_context)

  ngx.say(cjson.encode(content))
end

return _M
