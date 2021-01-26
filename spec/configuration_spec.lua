local configuration = require 'apicast.configuration'
local env = require 'resty.env'

describe('Configuration object', function()

  describe('provides information from the config file', function()
    local config = configuration.new({services = { 'a' }})

    it('returns services', function()
      assert.truthy(config.services)
      assert.equals(1, #config.services)
    end)
  end)

  describe('.parse_service', function()
    it('ignores empty hostname_rewrite', function()
      local config = configuration.parse_service({ proxy = { hostname_rewrite = '' }})

      assert.same(false, config.hostname_rewrite)
    end)

    it('populates hostname_rewrite', function()
      local config = configuration.parse_service({ proxy = { hostname_rewrite = 'example.com' }})

      assert.same('example.com', config.hostname_rewrite)
    end)

    it('has a default message, content-type, and status for the auth failed error', function()
      local config = configuration.parse_service({})

      assert.same('Authentication failed', config.error_auth_failed)
      assert.same('text/plain; charset=utf-8', config.auth_failed_headers)
      assert.equals(403, config.auth_failed_status)
    end)

    it('has a default message, content-type, and status for the missing creds error', function()
      local config = configuration.parse_service({})

      assert.same('Authentication parameters missing', config.error_auth_missing)
      assert.same('text/plain; charset=utf-8', config.auth_missing_headers)
      assert.equals(401, config.auth_missing_status)
    end)

    it('has a default message, content-type, and status for the no rules matched error', function()
      local config = configuration.parse_service({})

      assert.same('No Mapping Rule matched', config.error_no_match)
      assert.same('text/plain; charset=utf-8', config.no_match_headers)
      assert.equals(404, config.no_match_status)
    end)

    it('has a default message, content-type, and status for the limits exceeded error', function()
      local config = configuration.parse_service({})

      assert.same('Limits exceeded', config.error_limits_exceeded)
      assert.same('text/plain; charset=utf-8', config.limits_exceeded_headers)
      assert.equals(429, config.limits_exceeded_status)
    end)


    describe('policy_chain', function()

      it('works with null', function()
        local config = configuration.parse_service({ proxy = { policy_chain = ngx.null }})

        assert(config)
      end)

      it('ignores invalid policies in the chain', function()
        local config = configuration.parse_service({ proxy = { policy_chain = { { name = 'invalid' }, { name = 'echo' }, { name = 'echo' } } }})

        local policy_chain = config.policy_chain

        assert.equal(2, #policy_chain)
        assert.equal(2, table.maxn(policy_chain))
      end)
    end)

    describe('backend', function()
      it('defaults to fake backend', function()
        local config = configuration.parse_service({ proxy = {
          backend = nil
        }})

        assert.same('http://127.0.0.1:8081', config.backend.endpoint)
        assert.falsy(config.backend.host)
      end)

      it('is overriden from ENV', function()
        env.set('BACKEND_ENDPOINT_OVERRIDE', 'https://backend.example.com')

        local config = configuration.parse_service({ proxy = {
          backend = { endpoint = 'http://example.com', host = 'foo.example.com' }
        }})

        assert.same('https://backend.example.com', config.backend.endpoint)
        assert.same('backend.example.com', config.backend.host)
      end)

      it('detects TEST_NGINX_SERVER_PORT', function()
        env.set('TEST_NGINX_SERVER_PORT', '1954')

        local config = configuration.parse_service({ proxy = {
          backend = nil
        }})

        assert.same('http://127.0.0.1:1954', config.backend.endpoint)
        assert.falsy(config.backend.host)
      end)
    end)
  end)

  describe('.filter_services', function()
    local Service = require 'apicast.configuration.service'
    local filter_services = configuration.filter_services

    it('works with nil', function()
      local services = { Service.new({id="42"})}
      assert.equal(services, filter_services(services))
    end)

    it('works with table with ids', function()
      local services = { Service.new({id="42"})}
      assert.same(services, filter_services(services, { '42' }))
      assert.same({}, filter_services(services, { '21' }))
    end)

    describe("with service filter", function()

      local mockservices = {
        Service.new({id="42", hosts={"test.foo.com", "test.bar.com"}}),
        Service.new({id="12", hosts={"staging.foo.com"}}),
        Service.new({id="21", hosts={"prod.foo.com"}}),
      }

      it("with empty env variable", function()
        env.set('APICAST_SERVICES_FILTER_BY_URL', '')
        assert.same(filter_services(mockservices, nil), mockservices)
      end)

      it("it does not discard any service when there is not regex", function()
        assert.same(filter_services(mockservices, nil), mockservices)
      end)

      it("reads from environment variable", function()
        env.set('APICAST_SERVICES_FILTER_BY_URL', '.*.foo.com')
        assert.same(filter_services(mockservices, nil), mockservices)

        env.set('APICAST_SERVICES_FILTER_BY_URL', '^test.*')
        assert.same(filter_services(mockservices, nil), {mockservices[1]})

        env.set('APICAST_SERVICES_FILTER_BY_URL', '^(test|prod).*')
        assert.same(filter_services(mockservices, nil), {mockservices[1], mockservices[3]})
      end)

      it("matches the second host", function()
        env.set('APICAST_SERVICES_FILTER_BY_URL', '^test.bar.com')
        assert.same(filter_services(mockservices, nil), {mockservices[1]})
      end)

      it("validates invalid regexp", function()
        env.set('APICAST_SERVICES_FILTER_BY_URL', '^]')
        assert.same(filter_services(mockservices, nil), {})
      end)

      it("combination with service list", function()
        env.set('APICAST_SERVICES_FILTER_BY_URL', '^test.*')
        env.set('APICAST_SERVICES_LIST', '42,21')

        assert.same(filter_services(mockservices, {"21"}), {
          mockservices[1],
          mockservices[3]})

        assert.same(filter_services(mockservices, nil), {
          mockservices[1],
          mockservices[3]})
      end)
    end)

  end)

  describe('.filter_oidc_config', function()
    local Service = require 'apicast.configuration.service'
    local filter_oidc_config = configuration.filter_oidc_config

    local mockservices = {
      Service.new({id="42", hosts={"test.foo.com", "test.bar.com"}}),
      Service.new({id="12", hosts={"staging.foo.com"}}),
      Service.new({id="21", hosts={"prod.foo.com"}}),
    }

    it('works with nil', function()
      local res = filter_oidc_config(nil, nil)
      assert.same(res, {})
    end)


    it('if no id in oidc config returns correctly', function()
      local res = filter_oidc_config(mockservices, nil)
      assert.same(res, {})
    end)

    it("filter multiple services correctly", function()
      local oidc_config = {
        {service_id= 42, issuer="foo"},
        {service_id= 21, issuer="bar"},
      }
      local res = filter_oidc_config(mockservices, oidc_config)
      assert.same(res, oidc_config)
    end)

    it("OIDC config without id pass the filter", function()

      local oidc_config = {
        {issuer="foo"},
        {issuer="bar"},
      }
      local res = filter_oidc_config(mockservices, oidc_config)
      assert.same(res, oidc_config)
    end)

    it("OIDC config with invalid services are filter out", function()
      local oidc_config = {
        {service_id= 42, issuer="foo"},
        {service_id= 21, issuer="bar"},
        {service_id= 100, issuer="foobar"},
      }
      local res = filter_oidc_config(mockservices, oidc_config)
      assert.same(res, {
        {service_id= 42, issuer="foo"},
        {service_id= 21, issuer="bar"},
      })
    end)

    it("Services without oidc_config data", function()
      local oidc_config = {
        false,
        {service_id= 42, issuer="foo"},
        {service_id= 21, issuer="bar"},

      }
      local res = filter_oidc_config(mockservices, oidc_config)
      assert.same(res, {
        {},
        {service_id= 42, issuer="foo"},
        {service_id= 21, issuer="bar"},
      })
    end)

  end)

  insulate('.services_limit', function()
    local services_limit = configuration.services_limit

    it('reads from environment', function()
      env.set('APICAST_SERVICES', '42,21')

      local services = services_limit()

      assert.same({ ['42'] = true, ['21'] = true }, services)
    end)

    it('reads from environment', function()
      env.set('APICAST_SERVICES_LIST', '42,21')

      local services = services_limit()

      assert.same({ ['42'] = true, ['21'] = true }, services)
    end)

    it('reads from environment', function()
      env.set('APICAST_SERVICES', '')

      local services = services_limit()

      assert.same({}, services)
    end)

    it('reads from environment', function()
      env.set('APICAST_SERVICES_LIST', '')

      local services = services_limit()

      assert.same({}, services)
    end)

    it('reads from environment', function()
      env.set('APICAST_SERVICES_LIST', '42,21')
      env.set('APICAST_SERVICES', '')

      local services = services_limit()

      assert.same({ ['42'] = true, ['21'] = true }, services)
    end)

    it('reads from environment', function()
      env.set('APICAST_SERVICES', '42,21')
      env.set('APICAST_SERVICES_LIST', '')

      local services = services_limit()

      assert.same({ ['42'] = true, ['21'] = true }, services)
    end)
  end)

end)
