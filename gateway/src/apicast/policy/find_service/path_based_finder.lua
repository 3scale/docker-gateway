local mapping_rules_matcher = require 'apicast.mapping_rules_matcher'
local escape = require("resty.http.uri_escape")

local _M = {}

function _M.find_service(config_store, host)
  local found
  local services = config_store:find_by_host(host)
  local method = ngx.req.get_method()
  local uri = escape.escape_uri(ngx.var.uri)

  for s=1, #services do
    local service = services[s]
    local hosts = service.hosts or {}

    for h=1, #hosts do
      if hosts[h] == host then
        local name = service.system_name or service.id
        ngx.log(ngx.DEBUG, 'service ', name, ' matched host ', hosts[h])
        local matches = mapping_rules_matcher.matches(method, uri, {}, service.rules)
        -- matches() also returns the index of the first rule that matched.
        -- As a future optimization, in the part of the code that calculates
        -- the usage, we could use this to avoid trying to match again all the
        -- rules before the one that matched.

        if matches then
          found = service
          break
        end
      end
    end
    if found then break end
  end

  return found
end

return _M
