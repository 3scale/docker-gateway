local configuration = require('apicast.configuration_store')
local tablex = require("pl.tablex")

describe('Configuration Store', function()

  describe('.store', function()
    it('stores configuration', function()
      local store = configuration.new()
      local service = { id = '42', hosts = { 'example.com' } }

      store:store({services = { service }})

      assert.equal(service, store:find_by_id('42'))
    end)

    it('sets the configured flag to true', function()
      local store = configuration.new()

      store:store({ services = { id = '42', hosts = { 'example.com' } } })
      assert.truthy(store.configured)
    end)

    describe('when path routing is enabled', function()
      it('defines several services for the same host', function()
        local store = configuration.new(configuration.cache_size, { path_routing = true })
        local service1 = { id = '21', hosts = { 'example.com' } }
        local service2 = { id = '22', hosts = { 'example.com' } }

        store:store({ services = { service1, service2 } })

        assert.same({ service1, service2 }, store:find_by_host('example.com'))
      end)
    end)

    describe('when path routing is disabled', function()
      it('ignores defining a host for a service if already defined for another', function()
        local store = configuration.new(configuration.cache_size, { path_routing = false })
        local service1 = { id = '21', hosts = { 'example.com' } }
        local service2 = { id = '22', hosts = { 'example.com' } }

        store:store({ services = { service1, service2 } })

        assert.same({ service1 }, store:find_by_host('example.com'))
      end)
    end)

    it('stores config with OIDC', function()
      local store = configuration.new()
      local service_one = { id = '7', hosts = { 'example.com' } }
      local service_two = { id = '42', hosts = { 'oidc.example.com' } }

      assert(store:store({services = { service_one, service_two }, oidc = { ngx.null, ngx.null }}))
    end)
  end)

  describe('.find_by_id', function()
    it('returns an error when not initialized', function()
      local res, err = configuration:find_by_id()

      assert.falsy(res)
      assert.equal('not initialized', err)
    end)

    it('finds service by id', function()
      local store = configuration.new()
      local service = { id = '42' }

      store:add(service)

      assert.same(service, store:find_by_id('42'))
    end)

    it('does not seach by host', function()
      local store = configuration.new()
      local service = { id = '42', hosts = { 'example.com' } }

      store:add(service)

      assert.is_nil(store:find_by_id('example.com'))
    end)

    it('overrides previous values', function()
      local store = configuration.new()
      local first = { id = '42', hosts = { 'first.example.com' } }
      local second = { id = '42', hosts = { 'second.example.com' } }

      store:add(first)
      assert.equal(first, store:find_by_id('42'))

      store:add(second)
      assert.equal(second, store:find_by_id('42'))
    end)

    it('returns nil when the service does not exist', function()
      local store = configuration.new()

      assert.is_nil(store:find_by_id('42'))
    end)
  end)

  describe('.find_by_host', function()
    it('returns an error when not initialized', function()
      local res, err = configuration:find_by_host()

      assert.falsy(res)
      assert.equal('not initialized', err)
    end)

    it('returns stored services by host', function()
      local store = configuration.new()
      local service =  { id = '42', hosts = { 'example.com' } }

      store:add(service)

      assert.same({ service }, store:find_by_host('example.com'))
    end)

    it('works with multiple hosts', function()
      local store = configuration.new()
      local service =  { id = '21', hosts = { 'example.com', 'localhost' } }

      store:add(service)

      assert.same({ service }, store:find_by_host('example.com'))
      assert.same({ service }, store:find_by_host('localhost'))
    end)

    it('does not search by id', function()
      local store = configuration.new()
      local service = { id = '42' }

      store:add(service)

      assert.same({}, store:find_by_host('42'))
    end)

    it('returns empty array on no results', function()
      local store = configuration.new()

      assert.same({ }, store:find_by_host('unknown'))
    end)

    it('returns stale records by default', function()
      local store = configuration.new()
      local service =  { id = '21', hosts = { 'example.com' } }

      -- Can't add stale info with config.add. Need to do it through the
      -- internals of the object.
      store.cache:set('example.com', { service }, -1)

      assert.same({ service }, store:find_by_host('example.com'))
    end)

    it('does not return stale records when disabled', function()
      local store = configuration.new()
      local service =  { id = '21', hosts = { 'example.com' } }

      -- Can't add stale info with config.add. Need to do it through the
      -- internals of the object.
      store.cache:set('example.com', { service }, -1)

      assert.same({}, store:find_by_host('example.com', false))
    end)

    it('normalizes hosts to lowercase', function()
      local store = configuration.new()
      local service =  { id = '21', hosts = { 'EXAMPLE.com' } }

      store:add(service)

      assert.same({ service }, store:find_by_host('example.com'))
    end)
  end)

  describe('.reset', function()
    describe('when not initialized', function()
      it('returns an error', function()
        local res, err = configuration:reset()

        assert.falsy(res)
        assert.equal('not initialized', err)
      end)
    end)

    describe('when configured', function()
      local store

      before_each(function()
        store = configuration.new()
      end)

      it('deletes stored hosts', function()
        store.cache['example.com'] = { { '42'} }

        store:reset()

        assert.same({}, store.cache.hasht)
      end)

      it('deletes all services', function()
        store.services['42'] = {}

        store:reset()

        assert.same({}, store.services.hasht)
      end)

      it('sets configured flag', function()
        store.configured = true

        store:reset()

        assert.falsy(store.configured)
      end)

      it('resets de size of the services cache', function()
        local service1 = { id = '42', hosts = { 'example1.com' } }
        local service2 = { id = '43', hosts = { 'example2.com' } }

        store:reset(1)

        -- Add 2, as size is 1 only the second will be kept.
        store:add(service1)
        store:add(service2)

        assert.is_nil(store:find_by_id('42'))
        assert.equal(service2, store:find_by_id('43'))
      end)

      it('resets de size of the hosts cache', function()
        local service1 = { id = '42', hosts = { 'example1.com' } }
        local service2 = { id = '43', hosts = { 'example2.com' } }

        store:reset(1)

        -- Add 2, as size is 1 only the second will be kept.
        store:add(service1)
        store:add(service2)

        assert.same({}, store:find_by_host('example1.com'), false)
        assert.same({ service2 }, store:find_by_host('example2.com'), false)
      end)
    end)
  end)

  describe('.all', function()
    it('returns an error when not initialized', function()
      local res, err = configuration:all()

      assert.falsy(res)
      assert.equal('not initialized', err)
    end)

    it('returns all services', function()
      local store = configuration.new()

      local service1 = { id = '42' }
      local service2 = { id = '43' }

      store:add(service1)
      store:add(service2)

      assert.same({}, tablex.difference(store:all(), {service1, service2}, true))
    end)
  end)

  describe('.add', function()
    it('overrides previous services of the host', function()
      local store = configuration.new()
      local service1 = { id = '21', hosts = { 'example.com' } }
      local service2 = { id = '22', hosts = { 'example.com' } }

      store:add(service1)
      store:add(service2)

      assert.same({ service2 }, store:find_by_host('example.com'))
    end)
  end)
end)
