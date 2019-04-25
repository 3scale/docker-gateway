local _M = require('resty.http.proxy')
local env = require('resty.env')

describe('resty.http.proxy', function()
    before_each(function()
        _M:reset()
    end)

    context('.env', function()

        context('when no proxies are set', function()
            before_each(function()
                env.set('https_proxy', nil)
                env.set('HTTPS_PROXY', nil)
                env.set('http_proxy', nil)
                env.set('HTTP_PROXY', nil)
                env.set('all_proxy', nil)
                env.set('ALL_PROXY', nil)
                env.set('no_proxy', nil)
                env.set('NO_PROXY', nil)
            end)

            it('returns empty table', function()
                assert.same({}, _M.env())
            end)
        end)

        context('when http_proxy is set', function()
            before_each(function()
                env.set('http_proxy', 'http://localhost:8091')
            end)

            it('returns http_proxy', function()
                assert.contains({ http_proxy = 'http://localhost:8091' }, _M.env())
            end)
        end)

        context('when https_proxy is set', function()
            before_each(function()
                env.set('https_proxy', 'http://localhost:8091')
            end)

            it('returns http_proxy', function()
                assert.contains({ https_proxy = 'http://localhost:8091' }, _M.env())
            end)
        end)
    end)

    context('.new', function()
        it('connects to the #http_proxy', function()
            _M:reset({ http_proxy = 'http://127.0.0.1:1984' })

            local request = { url = 'http://127.0.0.1:1984/request', method = 'GET' }
            local proxy = assert(_M.new(request))

            local res = assert(proxy:request(request))

            assert.same(200, res.status)
            assert.match('GET http://127.0.0.1:1984/request HTTP/1.1', res:read_body())
        end)

        -- Regression test. Ref: https://issues.jboss.org/browse/THREESCALE-2205
        context('when different subdomains resolve to the same IP', function()
            local request_domain_1 = { url = 'http://test.example.com/', method = 'GET' }
            local request_domain_2 = { url = 'http://prod.example.com/', method = 'GET' }

            before_each(function()
                -- Make everything resolve to the same IP
                local resty_resolver = require 'resty.resolver.http'
                stub(resty_resolver, 'resolve', function() return "1.1.1.1", 80 end)
            end)

            context('and it uses a http proxy', function()
                before_each(function()
                    _M:reset({ http_proxy = 'http://127.0.0.1:1984' })
                end)

                it('does not reuse the connection', function()
                    local proxy = _M.new(request_domain_1)
                    proxy:request(request_domain_1):read_body()
                    proxy:set_keepalive()

                    proxy = _M.new(request_domain_2)
                    assert.same(0, proxy:get_reused_times())
                end)
            end)

            context('and it does not use an http proxy', function()
                before_each(function()
                    _M:reset({})
                end)

                it('does not reuse the connection', function()
                    local proxy = _M.new(request_domain_1)
                    proxy:request(request_domain_1):read_body()
                    proxy:set_keepalive()

                    proxy = _M.new(request_domain_2)
                    assert.same(0, proxy:get_reused_times())
                end)
            end)
        end)
    end)
end)
