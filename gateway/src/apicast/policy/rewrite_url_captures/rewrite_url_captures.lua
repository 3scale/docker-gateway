--- Rewrite URL Captures policy
-- This policy captures arguments in a URL and rewrites the URL using those
-- arguments.
-- For example, we can specify a matching rule with arguments like
-- '/{orderId}/{accountId}' and a template that specifies how to rewrite the
-- URL using those arguments, for example:
-- '/sales/v2/{orderId}?account={accountId}'.
-- In that case, the request '/123/456' will be transformed into
-- '/sales/v2/123?account=456'

local NamedArgsMatcher = require('named_args_matcher')
local QueryParams = require('apicast.query_params')

local ipairs = ipairs
local insert = table.insert

local policy = require('apicast.policy')
local _M = policy.new('Capture args policy')

local new = _M.new

function _M.new(config)
  local self = new(config)

  self.matchers = {}

  for _, transformation in ipairs(config.transformations or {}) do
    local matcher = NamedArgsMatcher.new(
      transformation.match_rule,
      transformation.template,
      transformation.methods
    )

    insert(self.matchers, matcher)
  end

  return self
end

local function change_uri(new_uri)
  ngx.req.set_uri(new_uri)
end

-- When a param in 'new_params' exist in the request, this function replaces
-- its value. When it does not exist, it simply adds it.
-- This function does not delete or modify the params in the query that do not
-- appear in 'new_params'.
local function set_query_params(params, param_vals)
  local query_params = QueryParams.new()

  for i = 1, #params do
    query_params:set(params[i], param_vals[i])
  end
end

-- This function only applies the first rule that matches.
-- Defining rules that take into account previous matches can become quite
-- complex and I don't think it's a common use case. Notice that it's possible
-- to do that anyway by chaining multiple instances of this policy.
function _M:rewrite()
  local uri = ngx.var.uri

  for _, matcher in ipairs(self.matchers) do
    local match, new_uri, params, param_vals = matcher:match(uri)

    if match then
      change_uri(new_uri)
      set_query_params(params, param_vals)
      return
    end
  end
end

return _M
