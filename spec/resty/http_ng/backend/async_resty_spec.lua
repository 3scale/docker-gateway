local backend = require 'resty.http_ng.backend.async_resty'

describe('resty backend', function()

  describe('GET method #network', function()
    local method = 'GET'

    it('accesses the url', function()
      local response = backend:send{method = method, url = 'http://example.com/'}
      assert.truthy(response)
      assert.falsy(response.error)
      assert.truthy(response.ok)
      assert.equal(200, response.status)
      assert.equal('string', type(response.body))
      assert.truthy(response.request)
    end)

    it('works with ssl', function()
      local response, err = backend:send{
        method = method, url = 'https://google.com/',
        -- This is needed because of https://groups.google.com/forum/#!topic/openresty-en/SuqORBK9ys0
        -- So far OpenResty can't use system certificated on demand.
        options = { ssl = { verify = false } }
      }
      assert.falsy(err)
      assert.falsy(response.error)
      assert.truthy(response.ok)
      assert(response.headers.location:match('^https://'))
      assert.equal('string', type(response.body))
      assert.truthy(response.request)
    end)

    it('returns proper error on connect timeout', function()
      local req = { method = method, url = 'http://example.com:81/', timeout = { connect = 1 } }

      local response = backend:send(req)

      assert.truthy(response)
      assert.equal('timeout', response.error)
      assert.equal(req, response.request)
      assert.falsy(response.ok)
    end)

    it('returns proper error on read timeout', function()
      local req = { method = method, url = 'http://httpbin.org/delay/1', timeout = { read = 1 } }

      local response = backend:send(req)

      assert.truthy(response)
      assert.equal('timeout', response.error)
      assert.equal(req, response.request)
      assert.falsy(response.ok)
    end)

    it('returns proper error on invalid ssl', function()
      local req = { method = method, url = 'https://untrusted-root.badssl.com/', options = { ssl = { verify = true } } }

      local response = backend:send(req)

      assert.truthy(response)
      assert.match('self signed certificate in certificate chain', response.error)
      assert.equal(req, response.request)
      assert.falsy(response.ok)
    end)

    it('returns proper error on invalid request', function()
      local req = { method = method }

      local response = backend:send(req)

      assert.truthy(response)
      assert.match('failed to create async request', response.error)
      assert.equal(req, response.request)
      assert.falsy(response.ok)
    end)

    context('http proxy is set', function()
      before_each(function()
        stub(require('resty.http.proxy'), 'active', true)
      end)

      it('returns error', function()
        local res = assert(backend:send{method = method, url = 'http://localhost:8081' })

        assert.contains({ error = 'async resty backend does not support proxy' }, res)
      end)
    end)

  end)

  describe('when there is no error', function()
    local response
    before_each(function()
      response = backend:send{ method = 'GET', url = 'http://127.0.0.1:1984' }
    end)

    it('is ok', function()
      assert.equal(true, response.ok)
    end)

    it('has no error', function()
      assert.equal(nil, response.error)
    end)
  end)

  describe('when there is error', function()
    local response
    before_each(function()
      response = backend:send{ method = 'GET', url = 'http://127.0.0.1:1' }
    end)

    it('is not ok', function()
      assert.equal(false, response.ok)
    end)

    it('has error', function()
      assert.same('string', type(response.error)) -- depending on the openresty version it can be "timeout" or "connection refused"
    end)
  end)
end)
