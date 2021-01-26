local PathBasedFinder = require('apicast.policy.find_service.path_based_finder')
local Configuration = require('apicast.configuration')
local ConfigurationStore = require('apicast.configuration_store')

describe('PathBasedFinder', function()
  -- The config_store depends on the path routing setting.
  local config_store_opts = { path_routing = true }

  describe('.find_service', function()
    it('returns the service for the host that has a rule that matches the request path', function()
      -- We access ngx.var.uri, ngx.req.get_method, and ngx.req.get_uri_args
      -- directly in the code, so we need to mock them. We should probably
      -- try to avoid this kind of coupling.
      ngx.var = { uri = '/def' }
      stub(ngx.req, 'get_uri_args', function() return {} end)
      stub(ngx.req, 'get_method', function() return 'GET' end)

      local host = 'example.com'

      local service_not_matching_1 = Configuration.parse_service({
        id = 1,
        proxy = {
          hosts = { host },
          proxy_rules = { { pattern = '/abc', http_method = 'GET',
                            metric_system_name = 'hits', delta = 1 } }
        }
      })

      local service_matching = Configuration.parse_service({
        id = 2,
        proxy = {
          hosts = { host },
          proxy_rules = { { pattern = '/def', http_method = 'GET',
                            metric_system_name = 'hits', delta = 2 } }
        }
      })

      local service_not_matching_2 = Configuration.parse_service({
        id = 3,
        proxy = {
          hosts = { host },
          proxy_rules = { { pattern = '/ghi', http_method = 'GET',
                            metric_system_name = 'hits', delta = 3 } }
        }
      })

      local services = { service_not_matching_1, service_matching, service_not_matching_2 }
      local config_store = ConfigurationStore.new(nil, config_store_opts)
      config_store:store({ services = services })

      local service_found = PathBasedFinder.find_service(config_store, host)

      assert.equal(service_matching, service_found)
    end)

    it('does not return a service if it matches the path but not the host', function()
      ngx.var = { uri = '/' }
      stub(ngx.req, 'get_uri_args', function() return {} end)
      stub(ngx.req, 'get_method', function() return 'GET' end)

      local host = 'example.com'

      local service_matching_path = Configuration.parse_service({
        id = 1,
        proxy = {
          hosts = { 'another_host.something' },
          proxy_rules = { { pattern = '/', http_method = 'GET',
                            metric_system_name = 'hits', delta = 2 } }
        }
      })

      local config_store = ConfigurationStore.new(nil, config_store_opts)
      config_store:store({ services = { service_matching_path } })

      local service_found = PathBasedFinder.find_service(config_store, host)

      assert.is_nil(service_found)
    end)

    it('does not return a service if it does not match neither the path nor the host', function()
      ngx.var = { uri = '/abc' }
      stub(ngx.req, 'get_uri_args', function() return {} end)
      stub(ngx.req, 'get_method', function() return 'GET' end)

      local host = 'example.com'

      local service = Configuration.parse_service({
        id = 1,
        proxy = {
          hosts = { 'another_host.something' },
          proxy_rules = { { pattern = '/dont_match', http_method = 'GET',
                            metric_system_name = 'hits', delta = 2 } }
        }
      })

      local config_store = ConfigurationStore.new(nil, config_store_opts)
      config_store:store({ services = { service } })

      local service_found = PathBasedFinder.find_service(config_store, host)

      assert.is_nil(service_found)
    end)

    it('returns the service if it matches the path, the host and the querystring params', function()
      ngx.var = { uri = '/abc' }
      stub(ngx.req, 'get_uri_args', function() return { foo = 'bar' } end)
      stub(ngx.req, 'get_method', function() return 'GET' end)

      local host = 'example.com'

      local service_not_matching = Configuration.parse_service({
        id = 1,
        proxy = {
          hosts = { host },
          proxy_rules = { { pattern = '/dont_match', http_method = 'GET',
                            metric_system_name = 'hits', delta = 2 } }
        }
      })

      local service_matching = Configuration.parse_service({
        id = 2,
        proxy = {
          hosts = { host },
          proxy_rules = { { pattern = '/abc',
                            querystring_parameters = { foo = '{bar}' },
                            http_method = 'GET', metric_system_name = 'hits',
                            delta = 2 } }
        }
      })

      local services = { service_not_matching, service_matching }
      local config_store = ConfigurationStore.new(nil, config_store_opts)
      config_store:store({ services = services })

      local service_found = PathBasedFinder.find_service(config_store, host)

      assert.equal(service_matching, service_found)
    end)

    it('returns nil if it matches the path, the host but not the querystring params', function()
      ngx.var = { uri = '/abc' }
      stub(ngx.req, 'get_uri_args', function() return { } end)
      stub(ngx.req, 'get_method', function() return 'GET' end)

      local host = 'example.com'

      local service_not_matching = Configuration.parse_service({
        id = 1,
        proxy = {
          hosts = { host },
          proxy_rules = { { pattern = '/dont_match', http_method = 'GET',
                            metric_system_name = 'hits', delta = 2 } }
        }
      })

      local service_matching = Configuration.parse_service({
        id = 2,
        proxy = {
          hosts = { host },
          proxy_rules = { { pattern = '/abc',
                            querystring_parameters = { foo = 'bar' },
                            http_method = 'GET', metric_system_name = 'hits',
                            delta = 2 } }
        }
      })

      local services = { service_not_matching, service_matching }
      local config_store = ConfigurationStore.new(nil, config_store_opts)
      config_store:store({ services = services })

      local service_found = PathBasedFinder.find_service(config_store, host)

      assert.is_nil(service_found)
    end)
  end)
end)
