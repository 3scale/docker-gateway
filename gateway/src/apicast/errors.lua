local _M = { }

local function exit()
  return ngx.exit(ngx.status)
end

function _M.no_credentials(service)
  ngx.log(ngx.INFO, 'no credentials provided for service ', service.id)
  ngx.var.cached_key = nil
  ngx.status = service.auth_missing_status
  ngx.header.content_type = service.auth_missing_headers
  ngx.print(service.error_auth_missing)
  return exit()
end

function _M.authorization_failed(service)
  ngx.log(ngx.INFO, 'authorization failed for service ', service.id)
  ngx.var.cached_key = nil
  ngx.status = service.auth_failed_status
  ngx.header.content_type = service.auth_failed_headers
  ngx.print(service.error_auth_failed)
  return exit()
end

function _M.limits_exceeded(service, retry_after)
  ngx.log(ngx.INFO, 'limits exceeded for service ', service.id)
  ngx.var.cached_key = nil

  if retry_after then
    ngx.header['Retry-After'] = retry_after
  end

  ngx.status = service.limits_exceeded_status
  ngx.header.content_type = service.limits_exceeded_headers
  ngx.print(service.error_limits_exceeded)
  return exit()
end

function _M.no_match(service)
  ngx.header.x_3scale_matched_rules = ''
  ngx.log(ngx.INFO, 'no rules matched for service ', service.id)
  ngx.var.cached_key = nil
  ngx.status = service.no_match_status
  ngx.header.content_type = service.no_match_headers
  ngx.print(service.error_no_match)
  return exit()
end

function _M.service_not_found(host)
  ngx.status = 404
  ngx.print('')
  ngx.log(ngx.WARN, 'could not find service for host: ', host or ngx.var.host)
  return exit()
end


function _M.upstream_not_found(service)
  ngx.status = 404
  ngx.print('')
  ngx.log(ngx.WARN, 'could not find upstream for service: ', service.id)
  return exit()
end


return _M
