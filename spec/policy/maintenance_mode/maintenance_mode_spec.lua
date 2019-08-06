local MaintenancePolicy = require('apicast.policy.maintenance_mode')

describe('Maintenance mode policy', function()
  describe('.rewrite', function()
    before_each(function()
      stub(ngx, 'say')
      stub(ngx, 'exit')
      ngx.header = {}
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

      it('returns the default Content-Type header', function()
        maintenance_policy:rewrite()

        assert.equals('text/plain; charset=utf-8', ngx.header['Content-Type'])
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

    context('when using a custom content type', function()
      it('sets the Content-Type header accordingly', function()
        local custom_content_type = 'application/json'
        local maintenance_policy = MaintenancePolicy.new(
            {
              message = '{ "msg": "some_msg" }',
              message_content_type = custom_content_type
            }
        )


        maintenance_policy:rewrite()

        assert.equals('application/json', ngx.header['Content-Type'])
      end)
    end)
  end)
end)
