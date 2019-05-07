local UpstreamConnectionPolicy = require('apicast.policy.upstream_connection')

describe('Upstream connection policy', function()
  describe('.export', function()
    it('returns the timeouts included in the config', function()
      local config_timeouts = {
        connect_timeout = 1,
        send_timeout = 2,
        read_timeout = 3
      }
      local policy = UpstreamConnectionPolicy.new(config_timeouts)

      local exported = policy:export()

      assert.same(config_timeouts, exported.upstream_connection_opts)
    end)

    it('does not return timeout params that is not in the config', function()
      local config_timeouts = { connect_timeout = 1 } -- Missing send and read
      local policy = UpstreamConnectionPolicy.new(config_timeouts)

      local exported = policy:export()

      assert.same(config_timeouts, exported.upstream_connection_opts)
    end)
  end)
end)
