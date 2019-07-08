local policy = require('apicast.policy')
local _M = policy.new('3scale Referrer policy', 'builtin')

function _M.rewrite(_, context)
  local referrer = ngx.var.http_referer

  if referrer then
    if context.proxy then
      context.proxy.extra_params_backend_authrep.referrer = referrer
    else
      ngx.log(ngx.ERR, 'Did not find a proxy in the policies context.')
    end
  end
end

return _M
