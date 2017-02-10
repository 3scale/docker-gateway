local round_robin = require 'resty.balancer.round_robin'
local newrelic = require('resty.newrelic')
local traceback = debug.traceback
local tostring = tostring

local _M = { }

function _M.call()
  local nr_transaction_id = ngx.ctx.nr_transaction_id
  local balancer = round_robin.new()
  local host = ngx.var.proxy_host -- NYI: return to lower frame
  local peers = balancer:peers(ngx.ctx[host])
  local peer, err = balancer:set_peer(peers)

  if not peer then
    if nr_transaction_id then
      newrelic.notice_transaction_error('failed to set peer', err, traceback(), "\n")
    end

    ngx.status = ngx.HTTP_SERVICE_UNAVAILABLE
    ngx.log(ngx.ERR, "failed to set current backend peer: ", err)
    ngx.exit(ngx.status)
  end

  if nr_transaction_id then
    ngx.var.upstream_transaction_id = newrelic.begin_external_segment(nr_transaction_id,
      newrelic.NEWRELIC_ROOT_SEGMENT, ngx.var.scheme .. '://' .. tostring(peer) .. ngx.var.uri, ngx.req.get_method())
  end
end

return _M
