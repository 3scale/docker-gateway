--- Custom APICAST_MODULE which overrides post_action from original
--- https://github.com/3scale/apicast/blob/3.0-stable/apicast/src/apicast.lua

-- load and initialize the parent module
local apicast = require('apicast').new()

local _M = { _VERSION = '3.0.0', _NAME = 'APIcast with response metrics' }
local mt = { __index = setmetatable(_M, { __index = apicast }) }

function _M.new()
  return setmetatable({}, mt)
end

local function send_count_metrics()
  -- get the document count from the custom response header
  local document_count = ngx.resp.get_headers()['x-document-count'];
  local user_key = ngx.req.get_headers()['user_key'];

  -- only report metrics if the response was a success and the custom header exists
  if ngx.status == ngx.HTTP_OK and document_count then
    ngx.log(ngx.INFO, '[3scale-metrics] sending metric to 3scale document-count: ', document_count)
    local report = ngx.location.capture("/report_metric",
      {
        args = {
          user_key    = user_key,
          metric_name = 'document_count',
          count       = document_count
        },
        copy_all_vars = true
      }
    );

    if report.status == ngx.HTTP_ACCEPTED  then
      ngx.log(ngx.INFO, '[3scale-metrics] document_count metric succeeded ', report.status)
    else
      ngx.log(ngx.WARN, '[3scale-metrics] document_count metric update failed. status: ', report.status)
    end
  end
end

function _M:post_action()
  local request_id = ngx.var.original_request_id
  local post_action_proxy = self.post_action_proxy

  if not post_action_proxy then
    return nil, 'not initialized'
  end

  -- send custom metrics if this is a document search
  if ngx.var.request_uri:match '^/v1/documents' then
    send_count_metrics()
  end

  local p = ngx.ctx.proxy or post_action_proxy[request_id]

  post_action_proxy[request_id] = nil

  if p then
    return p:post_action()
  else
    ngx.log(ngx.INFO, 'could not find proxy for request id: ', request_id)
    return nil, 'no proxy for request'
  end
end

return _M
