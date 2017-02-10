local round_robin = require 'resty.balancer.round_robin'
local newrelic = require('resty.newrelic')
local traceback = debug.traceback
local tostring = tostring

local _M = { }

function _M.call()
  local nr_transaction_id = ngx.ctx.nr_transaction_id or ngx.var.nr_transaction_id
  local balancer = round_robin.new()
  local host = ngx.var.proxy_host -- NYI: return to lower frame
  local peers = balancer:peers(ngx.ctx[host])
  local peer, err = balancer:set_peer(peers)

  if nr_transaction_id then
    ngx.var.upstream_transaction_id = newrelic.begin_external_segment(nr_transaction_id,
      newrelic.NEWRELIC_AUTOSCOPE, host .. '/' .. ngx.req.get_method(), ngx.var.uri)
  end

  if not peer then
    if nr_transaction_id then
      newrelic.notice_transaction_error(nr_transaction_id, 'failed to set peer', tostring(err), traceback(), "\n")
    end

    -- TODO: this does not set the HTTP status as it is supposed to
    ngx.status = ngx.HTTP_SERVICE_UNAVAILABLE
    ngx.log(ngx.ERR, "failed to set current ", host, " peer: ", err)
    ngx.exit(ngx.HTTP_SERVICE_UNAVAILABLE)
  end
end

return _M
