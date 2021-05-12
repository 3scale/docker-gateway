local FindService = require('apicast.policy.find_service')
local HostBasedFinder = require('apicast.policy.find_service.host_based_finder')
local PathBasedFinder = require('apicast.policy.find_service.path_based_finder')
local ConfigurationStore = require('apicast.configuration_store')

describe('find_service', function()
  describe('.rewrite', function()
    describe('when path routing is enabled', function()
      describe('and there is a service with a matching path', function()
        it('stores that service in the context', function()
          ConfigurationStore.path_routing = true
          local service = { id = '1' }
          local context = { configuration = ConfigurationStore.new(), host = 'example.com' }
          stub(PathBasedFinder, 'find_service', function(config_store, host)
            if config_store == context.configuration and host == context.host then
              return service
            end
          end)
          stub(HostBasedFinder, 'find_service')
          local find_service = FindService.new()

          find_service:rewrite(context)

          assert.stub(HostBasedFinder.find_service).was_not_called()
          assert.equals(service, context.service)
        end)
      end)

      describe('and fallback to find by host is enabled', function()
        before_each(function()
          ConfigurationStore.path_routing = true
          ConfigurationStore.path_routing_only = false
        end)

        it('finds the service by host and stores it in the context', function()
          local service = { id = '1' }
          local context = { configuration = ConfigurationStore.new(), host = 'example.com' }
          stub(PathBasedFinder, 'find_service', function() return nil end)
          stub(HostBasedFinder, 'find_service', function(config_store, host)
            if config_store == context.configuration and host == context.host then
              return service
            end
          end)

          local find_service = FindService.new()

          find_service:rewrite(context)

          assert.equals(service, context.service)
        end)

        it('stores nil in the context if there is not a service for the host', function()
          local context = { }
          stub(PathBasedFinder, 'find_service', function() return nil end)
          stub(HostBasedFinder, 'find_service', function() return nil end)

          local find_service = FindService.new()

          find_service:rewrite(context)

          assert.is_nil(context.service)
        end)
      end)

      describe('and fallback to find by host is disabled', function()
        before_each(function()
          ConfigurationStore.path_routing = true
          ConfigurationStore.path_routing_only = true
        end)

        it('stores nil in the context even if there is a service for the host', function()
          local service = { id = '1' }
          local context = { configuration = ConfigurationStore.new(), host = 'example.com' }
          stub(PathBasedFinder, 'find_service', function() return nil end)
          stub(HostBasedFinder, 'find_service', function(config_store, host)
            if config_store == context.configuration and host == context.host then
              return service
            end
          end)

          local find_service = FindService.new()

          find_service:rewrite(context)

          assert.is_nil(context.service)
        end)
      end)
    end)

    describe('when path routing is disabled', function()
      before_each(function()
        ConfigurationStore.path_routing = false
        ConfigurationStore.path_routing_only = false
      end)

      it('finds the service by host and stores it in the context', function()
        local service = { id = '1' }
        local context = { configuration = ConfigurationStore.new(), host = 'example.com' }
        stub(HostBasedFinder, 'find_service', function(config_store, host)
          if config_store == context.configuration and host == context.host then
            return service
          end
        end)
        stub(PathBasedFinder, 'find_service')
        local find_service = FindService.new()

        find_service:rewrite(context)

        assert.stub(PathBasedFinder.find_service).was_not_called()
        assert.equals(service, context.service)
      end)

      it('stores nil in the context if there is not a service for the host', function()
        local context = { }
        stub(HostBasedFinder, 'find_service', function() return nil end)
        local find_service = FindService.new()

        find_service:rewrite(context)

        assert.is_nil(context.service)
      end)
    end)
  end)

  describe('.ssl_certificate', function()
    -- Path based routing is not used when using ssl. It fallbacks to finding
    -- the service by host.
    for _, path_routing in ipairs({ true, false }) do
      describe("when path routing = " .. tostring(path_routing), function()
        ConfigurationStore.path_routing = path_routing

        it('return nil because path is not accesible on ssl phase', function()
          local context = { configuration = ConfigurationStore.new(), host = 'example.com' }
          local find_service = FindService.new()
          find_service:ssl_certificate(context)
          assert.falsy(context.service)
        end)

        it('stores nil in the context if there is not a service for the host', function()
          local context = { }
          stub(HostBasedFinder, 'find_service', function() return nil end)
          local find_service = FindService.new()

          find_service:ssl_certificate(context)

          assert.is_nil(context.service)
        end)
      end)
    end
  end)
end)
