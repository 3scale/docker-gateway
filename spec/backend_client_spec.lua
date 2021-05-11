local _M = require('apicast.backend_client')
local configuration = require('apicast.configuration')
local http_ng = require 'resty.http_ng'
local http_ng_resty = require 'resty.http_ng.backend.resty'
local ReportsBatch = require 'apicast.policy.3scale_batcher.reports_batch'
local backend_calls_metrics = require 'apicast.metrics.3scale_backend_calls'

function encode(data)
  tablex = require "pl.tablex"

  if tablex.size(data) == 0 then
    return ""
  end

  local result = ""
  local first = true

  for k,v in tablex.sort(data) do
    local prefix = "&"
    if first then
      prefix = ""
      first = false
    end
    result = string.format("%s%s%s=%s",result, prefix, k, v)
  end
  return result
end

describe('backend client', function()

  local test_backend
  local options_header_oauth_native = 'rejection_reason_header=1&limit_headers=1'
  local options_header_no_oauth_native = 'rejection_reason_header=1&limit_headers=1&no_body=1'

  before_each(function()
    stub(ngx, 'encode_args', encode)
    test_backend = http_ng.backend()
    stub(backend_calls_metrics, 'report')
  end)

  describe('authrep', function()
    it('works without params', function()
      local service = configuration.parse_service({
        id = '42', backend_version = '1',
        proxy = {
          backend = { endpoint = 'http://example.com' },
        },
        backend_authentication_type = 'auth', backend_authentication_value = 'val'
      })
      test_backend.expect{
        url = 'http://example.com/transactions/authrep.xml?' ..
            ngx.encode_args({ auth = service.backend_authentication.value, service_id = service.id }),
        headers = { host = 'example.com',
                    ['3scale-options'] = options_header_no_oauth_native }
      }.respond_with{ status = 200 }
      local backend_client = assert(_M:new(service, test_backend))

      local res = backend_client:authrep()

      assert.equal(200, res.status)
    end)

    it('passes params along', function()
      local service = configuration.parse_service({
        id = '42', backend_version = '1',
        proxy = {
          backend = { endpoint = 'http://example.com' },
        },
        backend_authentication_type = 'auth', backend_authentication_value = 'val'
      })
      test_backend.expect{
        url = 'http://example.com/transactions/authrep.xml?' ..
          string.format("auth=val&service_id=42&usage[hits]=1&user_key=foobar"),
        headers = { ['3scale-options'] = options_header_no_oauth_native }
      }.respond_with{ status = 200 }
      local backend_client = assert(_M:new(service, test_backend))

      local res = backend_client:authrep({ ['usage[hits]'] = 1 }, { user_key = 'foobar' })

      assert.equal(200, res.status)
    end)

    it('can override backend host header', function()
      local service = configuration.parse_service({
        id = '42', backend_version = '1',
        proxy = {
          backend = { endpoint = 'http://example.com', host = 'foo.example.com' },
        }
      })
      test_backend.expect{
        url = 'http://example.com/transactions/authrep.xml?service_id=42',
        headers = { host = 'foo.example.com',
                    ['3scale-options'] = options_header_no_oauth_native }
      }.respond_with{ status = 200 }
      local backend_client = assert(_M:new(service, test_backend))

      local res = backend_client:authrep()

      assert.equal(200, res.status)
    end)

    it('detects oauth native', function()
      local service = configuration.parse_service({
        id = '42', backend_version = 'oauth',
        proxy = {
          backend = { endpoint = 'http://example.com' },
        }
      })
      test_backend.expect{
        url = 'http://example.com/transactions/oauth_authrep.xml?service_id=42',
        headers = { ['3scale-options'] = options_header_oauth_native }
      }.respond_with{ status = 200 }
      local backend_client = assert(_M:new(service, test_backend))

      local res = backend_client:authrep()

      assert.equal(200, res.status)
    end)

    it('detects OIDC', function()
      local service = configuration.parse_service({
        id = '42', backend_version = 'oauth',
        proxy = {
          authentication_method = 'oidc',
          backend = { endpoint = 'http://example.com' },
        }
      })
      test_backend.expect{
        url = 'http://example.com/transactions/oauth_authrep.xml?service_id=42',
        headers = { ['3scale-options'] = options_header_no_oauth_native }
      }.respond_with{ status = 200 }
      local backend_client = assert(_M:new(service, test_backend))

      local res = backend_client:authrep()

      assert.equal(200, res.status)
    end)

    it('reports the call with the status', function()
      local service = configuration.parse_service({ id = '42' })
      local status = 200
      test_backend.expect({}).respond_with({ status = status })
      local backend_client = assert(_M:new(service, test_backend))

      backend_client:authrep()

      assert.stub(backend_calls_metrics.report).was_called_with('authrep', status)
    end)
  end)

  describe('authorize', function()
    it('works without params', function()
      local service = configuration.parse_service({
        id = '42', backend_version = '1',
        proxy = {
          backend = { endpoint = 'http://example.com' },
        },
        backend_authentication_type = 'auth', backend_authentication_value = 'val'
      })
      test_backend.expect{
        url = 'http://example.com/transactions/authorize.xml?' ..
            ngx.encode_args({ service_id = service.id, auth = service.backend_authentication.value }),
        headers = { host = 'example.com',
                    ['3scale-options'] = options_header_no_oauth_native }
      }.respond_with{ status = 200 }
      local backend_client = assert(_M:new(service, test_backend))

      local res = backend_client:authorize()

      assert.equal(200, res.status)
    end)

    it('passes params along', function()
      local service = configuration.parse_service({
        id = '42', backend_version = '1',
        proxy = {
          backend = { endpoint = 'http://example.com' },
        },
        backend_authentication_type = 'auth', backend_authentication_value = 'val'
      })
      test_backend.expect{
        url = 'http://example.com/transactions/authorize.xml?' ..
        string.format("auth=%s&service_id=%s&usage[hits]=1&user_key=foobar",service.backend_authentication.value, service.id),
        headers = { ['3scale-options'] = options_header_no_oauth_native }
      }.respond_with{ status = 200 }
      local backend_client = assert(_M:new(service, test_backend))

      local res = backend_client:authorize({ ['usage[hits]'] = 1 }, { user_key = 'foobar' })

      assert.equal(200, res.status)
    end)

    it('can override backend host header', function()
      local service = configuration.parse_service({
        id = '42', backend_version = '1',
        proxy = {
          backend = { endpoint = 'http://example.com', host = 'foo.example.com' },
        }
      })
      test_backend.expect{
        url = 'http://example.com/transactions/authorize.xml?service_id=42',
        headers = { host = 'foo.example.com',
                    ['3scale-options'] = options_header_no_oauth_native }
      }.respond_with{ status = 200 }
      local backend_client = assert(_M:new(service, test_backend))

      local res = backend_client:authorize()

      assert.equal(200, res.status)
    end)

    it('detects oauth', function()
      local service = configuration.parse_service({
        id = '42', backend_version = 'oauth',
        proxy = {
          backend = { endpoint = 'http://example.com' },
        }
      })
      test_backend.expect{
        url = 'http://example.com/transactions/oauth_authorize.xml?service_id=42',
        headers = { ['3scale-options'] = options_header_oauth_native }
      }.respond_with{ status = 200 }
      local backend_client = assert(_M:new(service, test_backend))

      local res = backend_client:authorize()

      assert.equal(200, res.status)
    end)

    it('detects oauth', function()
      local service = configuration.parse_service({
        id = '42', backend_version = 'oauth',
        proxy = {
          authentication_method = 'oidc',
          backend = { endpoint = 'http://example.com' },
        }
      })
      test_backend.expect{
        url = 'http://example.com/transactions/oauth_authorize.xml?service_id=42',
        headers = { ['3scale-options'] = options_header_no_oauth_native }
      }.respond_with{ status = 200 }
      local backend_client = assert(_M:new(service, test_backend))

      local res = backend_client:authorize()

      assert.equal(200, res.status)
    end)

    it('reports the call with the status', function()
      local service = configuration.parse_service({ id = '42' })
      local status = 200
      test_backend.expect({}).respond_with({ status = status })
      local backend_client = assert(_M:new(service, test_backend))

      backend_client:authorize()

      assert.stub(backend_calls_metrics.report).was_called_with('auth', status)
    end)

    it('retries when auth return a "closed" error and uses the "resty" http backend', function()
      local service = configuration.parse_service({ id = '42' })

      local backend_client = assert(_M:new(service, http_ng_resty))
      stub(backend_client.http_client, 'get').returns(
        { status = 0, error = 'closed' }
      )

      backend_client:authorize()

      assert.stub(backend_client.http_client.get).was_called(2)
    end)
  end)

  describe('report', function()
    describe('when the service is configured to use app IDs', function()
      it('makes the call to backend with the right params', function()
        local service = configuration.parse_service({
          id = '42',
          backend_version = '2',
          proxy = { backend = { endpoint = 'http://example.com' } },
          backend_authentication_type = 'auth', backend_authentication_value = 'val'
        })

        -- It's tricky to test with several reports because they can go in
        -- any order in the request.
        local reports = { { app_id = 'id1', metric = 'm1', value = 1 } }

        local transactions = {}
        transactions["transactions[0][app_id]"] = 'id1'
        transactions["transactions[0][usage][m1]"] = 1

        local reports_batch = ReportsBatch.new(service.id, reports)

        test_backend.expect{
          url = 'http://example.com/transactions.xml?' ..
              ngx.encode_args({ service_id = service.id,
                                auth = service.backend_authentication.value}),
          body = ngx.encode_args(transactions)
        }.respond_with{ status = 200 }

        local backend_client = assert(_M:new(service, test_backend))
        local res = backend_client:report(reports_batch)
        assert.equal(200, res.status)
      end)
    end)

    describe('when the service is configured to use user keys', function()
      it('makes the call to backend with the right params', function()
        local service = configuration.parse_service({
          id = '42',
          backend_version = '1',
          proxy = { backend = { endpoint = 'http://example.com' } },
          backend_authentication_type = 'auth', backend_authentication_value = 'val'
        })

        -- It's tricky to test with several reports because they can go in
        -- any order in the request.
        local reports = { { user_key = 'uk1', metric = 'm1', value = 1 } }

        local transactions = {}
        transactions["transactions[0][user_key]"] = 'uk1'
        transactions["transactions[0][usage][m1]"] = 1

        local reports_batch = ReportsBatch.new(service.id, reports)

        test_backend.expect{
          url = 'http://example.com/transactions.xml?' ..
              ngx.encode_args({ service_id = service.id,
                                auth = service.backend_authentication.value}),
          body = ngx.encode_args(transactions)
        }.respond_with{ status = 200 }

        local backend_client = assert(_M:new(service, test_backend))
        local res = backend_client:report(reports_batch)
        assert.equal(200, res.status)
      end)
    end)

    describe('when the service is configured to use oauth tokens', function()
      it('makes the call to backend with the right params', function()
        local service = configuration.parse_service({
          id = '42',
          backend_version = 'oauth',
          proxy = { backend = { endpoint = 'http://example.com' } },
          backend_authentication_type = 'auth', backend_authentication_value = 'val'
        })

        -- It's tricky to test with several reports because they can go in
        -- any order in the request.
        local reports = { { access_token = 'token', metric = 'm1', value = 1 } }

        local transactions = {}
        transactions["transactions[0][access_token]"] = 'token'
        transactions["transactions[0][usage][m1]"] = 1

        local reports_batch = ReportsBatch.new(service.id, reports)

        test_backend.expect{
          url = 'http://example.com/transactions.xml?' ..
              ngx.encode_args({ service_id = service.id,
                                auth = service.backend_authentication.value}),
          body = ngx.encode_args(transactions)
        }.respond_with{ status = 200 }

        local backend_client = assert(_M:new(service, test_backend))
        local res = backend_client:report(reports_batch)
        assert.equal(200, res.status)
      end)
    end)

    it('reports the call with the status', function()
      local service = configuration.parse_service({ id = '42' })
      local status = 200
      test_backend.expect({}).respond_with({ status = status })
      local backend_client = assert(_M:new(service, test_backend))

      backend_client:report(ReportsBatch.new(service.id, {}))

      assert.stub(backend_calls_metrics.report).was_called_with('report', status)
    end)
  end)

  describe('store_oauth_token', function()
    it('makes the right call to backend', function()


      local service_id = '42'
      local service = configuration.parse_service({
        id = service_id,
        backend_version = 'oauth',
        proxy = {
          backend = { endpoint = 'http://example.com' },
        },
        backend_authentication_type = 'service_token',
        backend_authentication_value = '123'
      })

      test_backend.expect{
        -- Notice that the service_id appears twice, but it's not a problem.
        url = 'http://example.com/services/42/'..
              'oauth_access_tokens.xml?service_id=42&service_token=123',
        body = 'app_id=an_app_id&token=my_token&ttl=3600&user_id=a_user_id'
      }.respond_with{ status = 200 }

      local backend_client = assert(_M:new(service, test_backend))

      local res = backend_client:store_oauth_token({
        app_id = 'an_app_id',
        token = 'my_token',
        ttl = 3600,
        user_id = 'a_user_id',
      })

      assert.equal(200, res.status)
    end)
  end)
end)
