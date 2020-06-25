local policy = require('apicast.policy')
local _M = policy.new('Content Caching', 'builtin')

local tab_insert = table.insert
local tab_new = require('resty.core.base').new_tab

local Rule = require("rule")

local prometheus = require('apicast.prometheus')
local metrics_updater = require('apicast.metrics.updater')

local content_cache_metric = prometheus('counter', "content_caching", "Content caching status", {"status"})

local new = _M.new

function _M.new(config)
  local self = new(config)

  self.rules = tab_new(#config.rules, 0)
  for _, config_rule in ipairs(config.rules or {}) do
    local rule, err = Rule.new_from_config_rule(config_rule)
    if rule then
      tab_insert(self.rules, rule)
    else
      ngx.log(ngx.WARN, "Cannot load content caching rule, err:", err)
    end
  end
  return self

end

function _M:access(context)
  ngx.var.cache_request = "true"
  for _, rule in ipairs(self.rules or {}) do
    local cond_is_true = rule.condition:evaluate(context)
    if cond_is_true and rule.cache then
      -- This is because `proxy_no_cache` directive is used, so we need to make
      -- the negative here.
      ngx.var.cache_request = (rule.cache and "" or "true")
      if rule.header and rule.header ~= "" then
        context[self] = {header = rule.header}
      end
      return
    end
  end
end

function _M:header_filter(context)
  -- Is not cached, no need to add the header
  if ngx.var.cache_request ~= "" then
    return
  end

  metrics_updater.inc(content_cache_metric, ngx.var.upstream_cache_status)
  ngx.log(ngx.INFO, "Request content caching status: ", ngx.var.upstream_cache_status)

  if context[self] and context[self].header then
    ngx.header[context[self].header] = ngx.var.upstream_cache_status
  end

end

return _M
