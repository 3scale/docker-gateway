local format = string.format

local resty_url = require "resty.url"
local resty_resolver = require 'resty.resolver'
local round_robin = require 'resty.balancer.round_robin'
local http_proxy = require 'resty.http.proxy'

local _M = { }

function _M.reset()
    _M.balancer = round_robin.new()
    _M.resolver = resty_resolver
    _M.http_backend = require('resty.http_ng.backend.resty')
    _M.dns_resolution = 'apicast' -- can be set to 'proxy' to let proxy do the name resolution

    return _M
end

local function resolve_servers(uri)
    local resolver = _M.resolver:instance()

    if not resolver then
        return nil, 'not initialized'
    end

    if not uri then
        return nil, 'no url'
    end

    return resolver:get_servers(uri.host, uri)
end

function _M.resolve(uri)
    local balancer = _M.balancer

    if not balancer then
        return nil, 'not initialized'
    end

    local servers, err = resolve_servers(uri)

    if err then
        return nil, err
    end

    local peers = balancer:peers(servers)
    local peer = balancer:select_peer(peers)

    local ip = uri.host
    local port = uri.port

    if peer then
        ip = peer[1]
        port = peer[2]
    end

    return ip, port
end

local function resolve(uri)
    local host = uri.host
    local port = uri.port

    if _M.dns_resolution == 'apicast' then
        host, port = _M.resolve(uri)
    end

    return host, port or resty_url.default_port(uri.scheme)
end

local function absolute_url(uri)
    local host, port = resolve(uri)

    return format('%s://%s:%s%s',
            uri.scheme,
            host,
            port,
            uri.path or '/'
    )
end

local function current_path(uri)
    return format('%s%s%s', uri.path or ngx.var.uri, ngx.var.is_args, ngx.var.query_string or '')
end

local function forward_https_request(proxy_uri, uri)
    -- This is needed to call ngx.req.get_body_data() below.
    ngx.req.read_body()

    local request = {
        uri = uri,
        method = ngx.req.get_method(),
        headers = ngx.req.get_headers(0, true),
        path = current_path(uri),

        -- We cannot use resty.http's .get_client_body_reader().
        -- In POST requests with HTTPS, the result of that call is nil, and it
        -- results in a time-out.
        body = ngx.req.get_body_data(),
        proxy_uri = proxy_uri
    }

    local httpc, err = http_proxy.new(request)

    if not httpc then
        ngx.log(ngx.ERR, 'could not connect to proxy: ',  proxy_uri, ' err: ', err)

        return ngx.exit(ngx.HTTP_SERVICE_UNAVAILABLE)
    end

    local res
    res, err = httpc:request(request)

    if res then
        httpc:proxy_response(res)
        httpc:set_keepalive()
    else
        ngx.log(ngx.ERR, 'failed to proxy request to: ', proxy_uri, ' err : ', err)
        return ngx.exit(ngx.HTTP_BAD_GATEWAY)
    end
end

local function get_proxy_uri(uri)
    local proxy_uri, err = http_proxy.find(uri)
    if not proxy_uri then return nil, err or 'invalid proxy url' end

    if not proxy_uri.port then
        proxy_uri.port = resty_url.default_port(proxy_uri.scheme)
    end

    return proxy_uri
end

function _M.find(upstream)
    return get_proxy_uri(upstream.uri)
end

function _M.request(upstream, proxy_uri)
    local uri = upstream.uri

    if uri.scheme == 'http' then -- rewrite the request to use http_proxy
        local err
        local host = upstream:set_host_header()
        upstream:use_host_header(host)
        upstream.servers, err = resolve_servers(proxy_uri)
        if err then
          ngx.log(ngx.WARN, "HTTP proxy is set, but no servers have been resolved, err: ", err)
        end
        upstream.uri.path = absolute_url(uri)
        upstream:rewrite_request()
        return
    elseif uri.scheme == 'https' then
        upstream:rewrite_request()
        forward_https_request(proxy_uri, uri)
        return ngx.exit(ngx.OK) -- terminate phase
    else
        ngx.log(ngx.ERR, 'could not connect to proxy: ',  proxy_uri, ' err: ', 'invalid request scheme')
        return ngx.exit(ngx.HTTP_BAD_GATEWAY)
    end
end

return _M.reset()
