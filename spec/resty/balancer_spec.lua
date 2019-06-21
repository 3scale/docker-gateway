local resty_balancer = require 'resty.balancer'
local round_robin = require 'resty.balancer.round_robin'

describe('resty.balancer', function()

  describe('.new', function()
    local new = resty_balancer.new

    it('accepts mode', function()
      local b, err = new(function() end)

      assert.equal('function', type(b.mode))
      assert.falsy(err)
    end)

    it('returns error on invalid mode', function()
      local b, err = new()

      assert.equal('missing balancing function', err)
      assert.falsy(b)
    end)
  end)

  describe(':peers', function()
    local balancer = resty_balancer.new(function() end)

    it('returns peers from servers', function()
      local servers = {
        { address = '127.0.0.2' }
      }

      local peers, err = balancer:peers(servers, 80)

      assert.falsy(err)
      assert.equal(1, #peers)
    end)
  end)

  describe(':set_peer', function()
    local b = resty_balancer.new(function(peers) return peers[1] end)
    b.balancer = { }

    it('returns peers from servers', function()
      local peers = {
        { '127.0.0.2', 8091 }
      }
      stub.new(b.balancer, 'set_current_peer', function() return true end)

      local ok, err = b:set_peer(peers)

      assert.falsy(err)
      assert.truthy(ok)
      assert.spy(b.balancer.set_current_peer).was.called_with('127.0.0.2', 8091)
    end)
  end)

  describe(':set_current_peer', function()
    it('returns ok when it sets the peer', function()
      local test = resty_balancer.new(function(peers) return peers[1] end)
      local set_current_peer = stub.new(test.balancer, 'set_current_peer', function() return true end)

      assert(test:set_current_peer('127.0.0.1', 8080))

      assert.spy(set_current_peer).was.called_with('127.0.0.1', 8080)
    end)
  end)

  describe('round-robin balancer', function()
    before_each(function() round_robin.reset() end)

    local balancer = round_robin.new()

    balancer.balancer = {
      set_current_peer = function() return true end
    }

    local servers = {
      { address = '127.0.0.1', port = 80 },
      { address = '127.0.0.2', port = 8080 },
      { address = '127.0.0.3', port = 8090 },
      query = 'example.com'
    }

    local peers = balancer:peers(servers)
    peers.cur = 1

    it(':set_peer loops through peers', function()
      local first = balancer:set_peer(peers)
      local second = balancer:set_peer(peers)
      local third = balancer:set_peer(peers)
      local fourth = balancer:set_peer(peers)

      assert.same({
        { '127.0.0.1', 80 },
        { '127.0.0.2', 8080 },
        { '127.0.0.3', 8090 },
        { '127.0.0.1', 80 },
      }, { first, second, third, fourth})
    end)

    it(':select_peer loops through peers', function()
      local first = balancer:select_peer(peers)
      local second = balancer:select_peer(peers)
      local third = balancer:select_peer(peers)

      assert.same({
        { '127.0.0.1', 80 },
        { '127.0.0.2', 8080 },
        { '127.0.0.3', 8090 }
      }, { first, second, third})
    end)

    it('returns error on empty peers', function()
      local peer, err = balancer:select_peer({})

      assert.same('empty peers', err)
      assert.falsy(peer)
    end)

    it('resets cursor when it overflows peers', function()
      local p = {'127.0.0.1', 8080 }
      local overflown_peers = { p , cur = 2, hash = 1234 }
      local peer, err = balancer:select_peer(overflown_peers)

      assert.equals(p, peer)
      assert.falsy(err)
    end)

  end)

  describe('set_timeouts', function()
    it('forwards the call to the internal balancer', function()
      local b = resty_balancer.new(function() end)
      b.balancer = { } -- Internal balancer
      stub.new(b.balancer, 'set_timeouts', function() end)

      b:set_timeouts(1, 2, 3)

      assert.stub(b.balancer.set_timeouts).was_called_with(1, 2, 3)
    end)

    it('returns an error when the internal balancer has not been set', function()
      local b = resty_balancer.new(function() end)
      b.balancer = nil -- Internal balancer

      local res, err = b:set_timeouts(1, 2, 3)

      assert.is_nil(res)
      assert.equals('balancer not available', err)
    end)
  end)

  describe('.retry_next_request', function()
    it('calls .set_more_tries(1) on the internal balancer', function()
      local b = resty_balancer.new(function() end)
      b.balancer = { } -- Internal balancer
      stub.new(b.balancer, 'set_more_tries', function() end)

      b:retry_next_request()

      assert.stub(b.balancer.set_more_tries).was_called_with(1)
    end)

    it('returns an error when the internal balancer has not been set', function()
      local b = resty_balancer.new(function() end)
      b.balancer = nil -- Internal balancer

      local res, err = b:retry_next_request()

      assert.is_nil(res)
      assert.equals('balancer not available', err)
    end)
  end)
end)
