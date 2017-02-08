local configuration = require 'configuration_store'

describe('Configuration Store', function()

  describe('.store', function()
    it('stores configuration', function()
      local store = configuration.new()
      local service = { id = '42', hosts = { 'example.com' } }

      store:store({services = { service }})

      assert.same({ ['42'] = service }, store.hosts['example.com'])
    end)
  end)

  describe('.find', function()
    it('returns stored services', function()
      local store = configuration.new()
      local service =  { 'service' }

      store.hosts['example.com'] = { ['42'] = service }

      assert.same({ ['42'] = service }, store:find('example.com'))
    end)

    it('finds service by id', function()
      local store = configuration.new()
      local service = { 'service' }

      store.services['42'] = service

      assert.same({ service }, store:find('42'))
    end)
  end)

  describe('.find_by_id', function()
    it('finds service by id', function()
      local store = configuration.new()
      local service = { 'service' }

      store.services['42'] = service

      assert.same({ service }, store:find('42'))
    end)
    it('it does not seach by host', function()
      local store = configuration.new()
      local service =  { 'service' }

      store.services['42'] = service
      store.hosts['example.com'] = { ['42'] = service }

      assert.is_nil(store:find_by_id('example.com'))
    end)
  end)

  describe('.find_by_host', function()
    it('returns stored services by host', function()
      local store = configuration.new()
      local service =  { 'service' }

      store.hosts['example.com'] = { ['42'] = service }

      assert.same({ ['42'] = service }, store:find('example.com'))
    end)

    it('does not search by id', function()
      local store = configuration.new()
      local service = { 'service' }

      store.hosts['example.com'] = { ['42'] = service }
      store.services['42'] = service

      assert.same({}, store:find_by_host('42'))
    end)
  end)

  describe('.reset', function()
    local store

    before_each(function()
      store = configuration.new()
    end)

    it('deletes stored hosts', function()
      store.hosts['example.com'] = { ['42'] = { } }

      store:reset()

      assert.equal(0, #store.hosts)
    end)

    it('deletes all services', function()
      store.services['42'] = {}

      store:reset()

      assert.equal(0, #store.services)
    end)

    it('sets configured flag', function()
      store.configured = true

      store:reset()

      assert.falsy(store.configured)
    end)
  end)

  describe('.all', function()
    it('returns all services', function()
      local store = configuration.new()

      store.services['42'] = { 'service' }

      assert.same({{'service'}}, store:all())
    end)
  end)
end)
