local apicast_balancer = require 'apicast.balancer'
local Upstream = require 'apicast.upstream'

describe('apicast.balancer', function()

  describe('.call', function()
    before_each(function ()
      ngx.var = {
        proxy_host = 'upstream'
      }
    end)

    it('sets default port from scheme if no port is specified for peers', function()
      local balancer = setmetatable({
        set_current_peer = spy.new(function() return true end),
      }, { __index = apicast_balancer.default_balancer })
      local upstream = Upstream.new('https://127.0.0.2')

      upstream.servers = {
        { address = '127.0.0.2', port = nil }
      }

      assert(apicast_balancer:call({ upstream =  upstream }, balancer))
      assert.spy(balancer.set_current_peer).was.called_with(balancer, '127.0.0.2', 443)
    end)

    it('sets the timeouts in the balancer when they are received in the context', function()
      local timeouts = {
        connect_timeout = 1,
        send_timeout = 2,
        read_timeout = 3,
      }

      local balancer = setmetatable({
        set_current_peer = spy.new(function() return true end),
        set_timeouts = spy.new(function() return true end),
      }, { __index = apicast_balancer.default_balancer })

      local upstream = Upstream.new('https://127.0.0.2')

      upstream.servers = {
        { address = '127.0.0.2', port = nil }
      }

      apicast_balancer:call(
          { upstream =  upstream,
            upstream_connection_opts = timeouts },
          balancer
      )

      assert.spy(balancer.set_timeouts).was_called_with(
          balancer,
          timeouts.connect_timeout,
          timeouts.send_timeout,
          timeouts.read_timeout
      )
    end)
  end)
end)
