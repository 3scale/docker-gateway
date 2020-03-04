local Upstream = require('apicast.upstream')
local match = require('luassert.match')

describe('Upstream', function()
    local valid_url = 'http://localhost:8080/path?query'

    describe('.new', function()
        it('returns an error on invalid upstream', function()
            assert.returns_error('invalid upstream', Upstream.new('invalid uri'))
        end)

        it('returns new instance', function()
            assert(Upstream.new(valid_url))
        end)

        it('returns table with location_name', function()
            -- @upstream location is defined in the apicast.conf file
            assert.equal('@upstream', Upstream.new(valid_url).location_name)
        end)

        it('returns table with upstream_name', function()
            -- upstream name is defined in the upstream.conf file
            assert.equal('upstream', Upstream.new(valid_url).upstream_name)
        end)

        it('returns table with resolver', function()
            assert.equal(require('resty.resolver'), Upstream.new(valid_url).resolver)
        end)
    end)

    describe(':resolve', function()
        it('uses .resolver', function()
            local upstream = Upstream.new('http://localhost:8080')
            local resolver, instance, servers = {'resolver'}, {'instance'}, {'response'}
            stub(resolver, 'instance').returns(instance)
            stub(instance, 'get_servers').returns(servers)

            upstream.resolver = resolver

            assert.equal(servers, upstream:resolve())
            assert.spy(instance.get_servers).was_called_with(instance, 'localhost', match.contains({ port = 8080 }))
        end)

        -- this is useful when we want to pre populate resolved servers in tests
        it('keeps and returns previously resolved servers', function()
            local upstream = Upstream.new(valid_url)
            local servers = { 'resolved servers instance' }
            upstream.servers = servers

            assert.equal(upstream.servers, upstream:resolve())
            assert.equal(upstream.servers, servers)
        end)
    end)

    describe(':port', function()
        it('returns port from the URI', function()
            assert.same(8090, Upstream.new('http://host:8090'):port())
        end)

        it('returns default port for the scheme when none is provided', function()
            assert.same(443, Upstream.new('https://example.com'):port())
        end)

        it('returns nil when port is unknown', function()
            assert.is_nil(Upstream.new('ftp://example.com'):port())
        end)
    end)


    describe(':append_path', function()
        it('return valid path when is not set', function()
            local up = Upstream.new('http://host:8090')
            up:append_path("/test")
            assert.same(up.uri.path, "/test")
        end)

        it('leading slash is removed', function()
            local up = Upstream.new('http://host:8090/')
            up:append_path("/test/")
            assert.same(up.uri.path, "/test/")
        end)

    end)

    local function stub_ngx_request()
        ngx.var = { }

        stub(ngx, 'exec')
        stub(ngx.req, 'set_header')
        stub(ngx.req, 'set_uri', function(uri)
            ngx.var.uri = uri
        end)
        stub(ngx.req, 'set_uri_args', function(args)
            ngx.var.args = args
            ngx.var.query_string = args
        end)
    end

    describe(':rewrite_request', function()
        before_each(stub_ngx_request)

        it('sets request Host header to the URI host', function()
            assert(Upstream.new('http://example.com/')):rewrite_request()

            assert.spy(ngx.req.set_header).was_called_with('Host', 'example.com')
        end)

        it('sets request uri to the upstream path', function()
            assert(Upstream.new('http://example.com/test-path')):rewrite_request()

            assert.spy(ngx.req.set_uri).was_called_with('/test-path')
        end)

        for url, path in pairs({
            ['http://example.com'] = '/',
            ['http://example.com/path'] = '/path',
            ['http://example.com/path/'] = '/path/',
            ['http://example.com/path/foo'] = '/path/foo',
            ['http://example.com/path/foo/'] = '/path/foo/',
            ['http://example.com/path?test=value/'] = '/path',
        }) do
            it(('/ uses path %s for upstream %s'):format(path, url), function()
                ngx.var.uri = '/'
                local upstream = Upstream.new(url)
                upstream:rewrite_request()
                assert.same(path, ngx.var.uri)
            end)
        end

        for url, path in pairs({
            ['http://example.com'] = '/test',
            ['http://example.com/path'] = '/path/test',
            ['http://example.com/path/'] = '/path/test',
            ['http://example.com/path/foo'] = '/path/foo/test',
            ['http://example.com/path/foo/'] = '/path/foo/test',
            ['http://example.com/path?test=value/'] = '/path/test',
        }) do
            it(('/test uses path %s for upstream %s'):format(path, url), function()
                ngx.var.uri = '/test'
                local upstream = Upstream.new(url)
                upstream:rewrite_request()
                assert.same(path, ngx.var.uri)
            end)
        end

        it('sets request query params to the upstream query params', function()
            assert(Upstream.new('http://example.com/?query=param')):rewrite_request()

            assert.spy(ngx.req.set_uri_args).was_called_with('query=param')
        end)

        it('does not set the request uri when there is no upstream path', function()
            assert(Upstream.new('http://example.com')):rewrite_request()

            assert.spy(ngx.req.set_uri).was_not_called()
        end)

        for url, host in pairs({
            ['http://example.com'] = 'example.com',
            ['http://example.com:80'] = 'example.com',
            ['http://example.com:8080'] = 'example.com:8080',
            ['https://example.com:80'] = 'example.com:80',
            ['https://example.com:443'] = 'example.com',
            ['https://example.com:8080'] = 'example.com:8080',
        }) do
            it(('upstream %s sets Host header to %s'):format(url, host), function()
                local upstream = Upstream.new(url)
                upstream:rewrite_request()
                assert.spy(ngx.req.set_header).was_called_with('Host', host)
            end)
        end

    end)

    describe(':call', function()
        before_each(stub_ngx_request)

        it('calls :resolve() when needed', function()
            local upstream = Upstream.new('http://example.com')
            stub(upstream, 'resolve')

            upstream:call({})

            assert.spy(upstream.resolve).was_called_with(upstream)
        end)

        it('does not call :resolve() when not needed', function()
            local upstream = Upstream.new('http://example.com')
            stub(upstream, 'resolve')

            upstream.servers = {}
            upstream:call({})

            assert.spy(upstream.resolve).was_not_called()
        end)

        it('stores itself in the context', function()
            local upstream = Upstream.new('http://localhost')
            local context = {}

            upstream:call(context)

            assert.equal(upstream, context[upstream.upstream_name])
        end)

        it('executes the upstream location when provided', function()
            local upstream = Upstream.new('http://localhost')

            upstream:call({})

            assert.spy(ngx.exec).was_called_with(upstream.location_name)
        end)

        it('skips executing the upstream location when missing', function()
            local upstream = Upstream.new('http://localhost')
            upstream.location_name = nil

            upstream:call({})

            assert.spy(ngx.exec).was_not_called()
        end)

        it('skips sending the response if it was already sent', function()
            ngx.headers_sent = true -- already sent response to the client
            local upstream = Upstream.new(valid_url)
            local context = { }
            spy.on(upstream, 'resolve')

            assert.returns_error('response sent already', upstream:call(context))

            assert.is_nil(context[upstream.upstream_name])
            assert.spy(upstream.resolve).was_not_called()
        end)

        describe('changes ngx.var.proxy_pass to upstream url', function()
            it('without port', function()
                local upstream = Upstream.new('http://localhost:8080/path?query')

                upstream:call({})

                assert.equal('http://upstream', ngx.var.proxy_pass)
            end)

            it('works with partial url', function()
                local upstream = Upstream.new('http://example.com')

                upstream:call({})

                assert.equal('http://upstream', ngx.var.proxy_pass)
            end)

            it('works with websocket url', function()
                local upstream = Upstream.new('ws://example.com')
                upstream:call({})
                assert.equal('http://upstream', ngx.var.proxy_pass)

                upstream = Upstream.new('wss://example.com')
                upstream:call({})
                assert.equal('https://upstream', ngx.var.proxy_pass)
            end)

        end)
    end)

    describe('http proxy', function()
        local resty_proxy = require('resty.http.proxy')
        local http_proxy = require('apicast.http_proxy')

        before_each(stub_ngx_request)

        describe('is active', function()
            before_each(function()
                resty_proxy:reset({ no_proxy = '*' })
            end)

            it('calls :rewrite_request()', function()
                local upstream = Upstream.new('http://example.com')
                stub(upstream, 'rewrite_request')

                upstream:call({})

                assert.spy(upstream.rewrite_request).was_called(1)
            end)
        end)

        describe('is not active', function()
            before_each(function()
                resty_proxy:reset({ http_proxy = 'http://localhost' })
            end)

            it('calls http_proxy.request()', function()
                local upstream = Upstream.new('http://example.com')
                stub(http_proxy, 'request')

                upstream:call({})

                assert.spy(http_proxy.request).was_called(1)
            end)
        end)
    end)

    describe('.use_host_header', function()
        before_each(stub_ngx_request)

        it('allows to set the host used when setting the Host Header', function()
            local upstream = Upstream.new('http://example.com')
            local host = 'http://another_host'

            upstream:use_host_header(host)
            upstream:rewrite_request()
            assert.spy(ngx.req.set_header).was_called_with('Host', host)
        end)
    end)

    describe(".set_host_header", function()

        before_each(stub_ngx_request)

        it('self.host is defined', function()
            local host = "test.com"
            local upstream = Upstream.new('http://example.com')
            upstream:use_host_header(host)

            local tmp_host, err = upstream:set_host_header()

            assert.equal(tmp_host, host)
            assert.falsy(err)
            assert.spy(ngx.req.set_header).was_called_with('Host', host)
        end)

        it('self.uri is not defined', function()
            local host = "test.com"
            local upstream = Upstream.new('http://example.com')
            upstream.uri = nil

            local tmp_host, err = upstream:set_host_header()

            assert.falsy(tmp_host, host)
            assert.equal(err, "Upstream URI not initialized")
        end)

        it('self.uri is defined in a not default port', function()
            local expected_host = "example.com:10000"
            local upstream = Upstream.new('http://example.com:10000')

            local tmp_host, err = upstream:set_host_header()

            assert.equal(tmp_host, expected_host)
            assert.falsy(err)
            assert.spy(ngx.req.set_header).was_called_with('Host', expected_host)
        end)

        it('self.uri is defined in a default port', function()
            local expected_host = "example.com"
            local upstream = Upstream.new('http://example.com')

            local tmp_host, err = upstream:set_host_header()

            assert.equal(tmp_host, expected_host)
            assert.falsy(err)
            assert.spy(ngx.req.set_header).was_called_with('Host', expected_host)
        end)
    end)
end)
