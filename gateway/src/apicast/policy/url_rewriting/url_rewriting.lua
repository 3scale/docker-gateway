--- URL rewriting policy
-- This policy allows to modify the path of a request.

local ipairs = ipairs
local sub = ngx.re.sub
local gsub = ngx.re.gsub

local policy = require('apicast.policy')
local _M = policy.new('URL rewriting policy')

local new = _M.new

local substitute_functions = { sub = sub, gsub = gsub }

-- func needs to be ngx.re.sub or ngx.re.gsub.
-- This method simply calls one of those 2. They have the same interface.
local function substitute(func, subject, regex, replace, options)
  local new_uri, num_changes, err = func(subject, regex, replace, options)

  if not new_uri then
    ngx.log(ngx.WARN, 'There was an error applying the regex: ', err)
  end

  return new_uri, num_changes > 0
end

-- Returns true when the URL was rewritten and false otherwise
local function apply_rewrite_command(command)
  local func = substitute_functions[command.op]

  if not func then
    ngx.log(ngx.WARN, "Unknown URL rewrite operation: ", command.op)
  end

  local new_uri, changed = substitute(
    func, ngx.var.uri, command.regex, command.replace, command.options)

  if changed then
    ngx.req.set_uri(new_uri)
  end

  return changed
end

--- Initialize a URL rewriting policy
-- @tparam[opt] table config Contains the rewrite commands.
-- The rewrite commands are based on the 'ngx.re.sub' and 'ngx.re.gsub'
-- functions provided by OpenResty. Please check
-- https://github.com/openresty/lua-nginx-module for more details.
-- Each rewrite command is a table with the following fields:
--
--   - op: can be 'sub' or 'gsub'.
--   - regex: regular expression to be matched.
--   - replace: string that will replace whatever is matched by the regex.
--   - options[opt]: options to control how the regex match will be done.
--     Accepted options are the ones in 'ngx.re.sub' and 'ngx.re.gsub'.
--   - break[opt]: defaults to false. When set to true, if the command rewrote
--     the URL, it will be the last command applied.
function _M.new(config)
  local self = new(config)
  self.commands = (config and config.commands) or {}
  return self
end

function _M:rewrite(context)
  -- Save original URI in the context in case other policies need it.
  context.original_uri = ngx.var.uri

  for _, command in ipairs(self.commands) do
    local rewritten = apply_rewrite_command(command)

    if rewritten and command['break'] then
      break
    end
  end
end

return _M
