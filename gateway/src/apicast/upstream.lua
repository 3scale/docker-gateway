--- @classmod Upstream
-- Abstracts how to forward traffic to upstream server.
--- @usage
--- local upstream = Upstream.new('http://example.com')
--- upstream:rewrite_request() -- set Host header to 'example.com'
--- -- store itself in `context` table for later use in balancer phase and call `ngx.exec`.
--- upstream:call(context)

local setmetatable = setmetatable
local str_format = string.format

local resty_resolver = require('resty.resolver')
local resty_url = require('resty.url')
local url_helper = require('resty.url_helper')

local http_proxy = require('apicast.http_proxy')
local format = string.format
local cjson = require('cjson')

local _M = {

}

local function proxy_pass(upstream)
    local scheme = upstream.uri.scheme
    if upstream.uri.scheme == "wss" then
        scheme = "https"
    end

    if upstream.uri.scheme == "ws" then
        scheme = "http"
    end

    return str_format('%s://%s', scheme, upstream.upstream_name)
end

local mt = {
    __index = _M
}

--- Create new Upstream instance.
--- @tparam string url
--- @treturn Upstream|nil upstream instance
--- @treturn nil|string error when upstream can't be initialized
--- @static
function _M.new(url)
    if not url or url == cjson.null then
        return nil, 'Upstream cannot be null'
    end
    local uri, err = url_helper.parse_url(url)
    if err then
        return nil, 'invalid upstream'
    end

    return setmetatable({
        uri = uri,
        resolver = resty_resolver,
        -- @upstream location is defined in apicast.conf
        location_name = '@upstream',
        -- upstream is defined in upstream.conf
        upstream_name = 'upstream',
    }, mt)
end

--- Resolve upstream servers.
--- @treturn {...}|nil resolved servers returned by the resolver
--- @treturn nil|string error in case resolving fails
function _M:resolve()
    local resolver = self.resolver
    local uri = self.uri

    if self.servers then
        return self.servers
    end

    if not resolver or not uri then return nil, 'not initialized' end

    local res, err = resolver:instance():get_servers(uri.host, uri)

    if err then
        return nil, err
    end

    self.servers = res

    return res
end

--- Return port to use when connecting to upstream.
--- @treturn number port number
function _M:port()
    if not self or not self.uri then
        return nil, 'not initialized'
    end

    return self.uri.port or resty_url.default_port(self.uri.scheme)
end

local root_uri = {
    ['/'] = true,
    [''] = true,
}

local function prefix_path(prefix)
    local uri = ngx.var.uri or ''

    if root_uri[uri] then return prefix end

    uri = resty_url.join(prefix, uri)

    return uri
end

local function host_header(uri)
    local port = uri.port
    local default_port = resty_url.default_port(uri.scheme)

    if port and port ~= default_port then
        return format('%s:%s', uri.host, port)
    else
        return uri.host
    end
end

function _M:use_host_header(host)
    self.host = host
end

function _M:set_path(path)
    self.uri.path, self.uri.query = url_helper.split_path(path)
end

function _M:append_path(path)
    local tmp_path, tmp_query = url_helper.split_path(path)
    if not self.uri.path then
      self.uri.path = "/"
    end
    self.uri.path = resty_url.join(self.uri.path, tmp_path)

    -- If query is already present, do not need to add more.
    if tmp_query and tmp_query ~= "" then
        return
    end
    self.uri.query = tmp_query
end

function _M:update_location(location_name)
  if location_name then
    self.location_name = location_name
  end
end

--- Rewrite request Host header to what is provided in the argument or in the URL.
function _M:rewrite_request()

    local _, err = self:set_host_header()
    if err then
      return nil, 'not initialized'
    end

    local uri = self.uri

    if uri.path then
        ngx.req.set_uri(prefix_path(uri.path))
    end

    if uri.query then
        ngx.req.set_uri_args(uri.query)
    end
end

local function exec(self)
    ngx.var.proxy_pass = proxy_pass(self)

    -- the caller can unset the location_name to do own exec/location.capture
    if self.location_name then
        ngx.exec(self.location_name)
    end
end

function _M:set_host_header()
    if self.host then
      ngx.req.set_header('Host', self.host)
      return self.host, nil
    end

    -- set Host from uri if Host is not defined
    local uri = self.uri
    if not uri then
      return nil, "Upstream URI not initialized"
    end
    local host = host_header(uri)
    ngx.req.set_header('Host', host)
    return host, nil
end

--- Execute the upstream.
--- @tparam table context any table (policy context, ngx.ctx) to store the upstream for later use by balancer
function _M:call(context)
    if ngx.headers_sent then return nil, 'response sent already' end

    local proxy_uri

    -- get_http_proxy is a property set by the http_proxy policy
    if context.get_http_proxy then
      proxy_uri = context.get_http_proxy(self.uri)
    else
      proxy_uri = http_proxy.find(self)
    end

    if proxy_uri then
        ngx.log(ngx.DEBUG, 'using proxy: ', proxy_uri)
        -- https requests will be terminated, http will be rewritten and sent
        -- to a proxy
        http_proxy.request(self, proxy_uri)
    else
        local err = self:rewrite_request()
        if err then
          ngx.log(ngx.WARN, "Upstream rewrite request failed:", err)
        end
    end

    if not self.servers then self:resolve() end

    context[self.upstream_name] = self

    return exec(self)
end

function _M:set_owner_id(owner_id)
  self.owner_id = owner_id
end

function _M:has_owner_id()
  return self.owner_id
end

return _M
