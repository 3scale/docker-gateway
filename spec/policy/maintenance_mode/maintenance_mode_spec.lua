local MaintenancePolicy = require('apicast.policy.maintenance_mode')

describe('Maintenance mode policy', function()
  describe('.rewrite', function()
    before_each(function()
      stub(ngx, 'say')
      stub(ngx, 'exit')
    end)

    context('when using the defaults', function()
      local maintenance_policy = MaintenancePolicy.new()

      it('returns 503', function()
        maintenance_policy:rewrite()

        assert.stub(ngx.exit).was_called_with(503)
      end)

      it('returns the default message', function()
        maintenance_policy:rewrite()

        assert.stub(ngx.say).was_called_with('Service Unavailable - Maintenance')
      end)
    end)

    context('when using a custom status code', function()
      it('returns that status code', function()
        local custom_code = 555
        local maintenance_policy = MaintenancePolicy.new(
            { status = custom_code }
        )

        maintenance_policy:rewrite()

        assert.stub(ngx.exit).was_called_with(custom_code)
      end)
    end)

    context('when using a custom message', function()
      it('returns that message', function()
        local custom_msg = 'Some custom message'
        local maintenance_policy = MaintenancePolicy.new(
            { message = custom_msg }
        )

        maintenance_policy:rewrite()

        assert.stub(ngx.say).was_called_with(custom_msg)
      end)
    end)
  end)
end)
