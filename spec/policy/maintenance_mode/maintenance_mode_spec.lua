local MaintenancePolicy = require('apicast.policy.maintenance_mode')
local ngx_variable = require('apicast.policy.ngx_variable')
   

describe('Maintenance mode policy', function()

  local test_host = 'backend.example.org'
  local test_host2 = 'backend2.example.org'
  local test_path = '/foo/bar/'
  local test_path2 = '/bar/foo/'

  describe('.access', function()
    before_each(function()
      local test_upstream = { uri = { scheme = 'https', host = test_host, port = '443', path = test_path } }
      ctx = { get_upstream = function() return test_upstream  end }
      stub(ngx, 'say')
      stub(ngx, 'exit')
      ngx.header = {}
      stub(ngx_variable, 'available_context', function(context) return context end)
    end)

    context('when using the defaults', function()
      local maintenance_policy = MaintenancePolicy.new()

      it('returns 503', function()
        maintenance_policy:access(ctx)

        assert.stub(ngx.exit).was_called_with(503)
      end)

      it('returns the default message', function()
        maintenance_policy:access(ctx)

        assert.stub(ngx.say).was_called_with('Service Unavailable - Maintenance')
      end)

      it('returns the default Content-Type header', function()
        maintenance_policy:access(ctx)

        assert.equals('text/plain; charset=utf-8', ngx.header['Content-Type'])
      end)
    end)

    context('when using a custom status code', function()
      it('returns that status code', function()
        local custom_code = 555
        local maintenance_policy = MaintenancePolicy.new(
            { status = custom_code }
        )

        maintenance_policy:access(ctx)

        assert.stub(ngx.exit).was_called_with(custom_code)
      end)
    end)

    context('when using a custom message', function()
      it('returns that message', function()
        local custom_msg = 'Some custom message'
        local maintenance_policy = MaintenancePolicy.new(
            { message = custom_msg }
        )

        maintenance_policy:access(ctx)

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
        maintenance_policy:access(ctx)
        assert.equals('application/json', ngx.header['Content-Type'])
      end)
    end)

    context('when Maintenance Mode is configured for a specific upstream', function()  
      it('returns 503', function()
        local maintenance_policy = MaintenancePolicy.new({
          condition = {
            operations = {{
              op="==", left="{{ upstream.scheme }}://{{ upstream.host }}{{ upstream.port }}{{ upstream.path }}", 
              left_type="liquid", right="https://"..test_host.."443"..test_path, right_type="plain"
            }},
            combine_op="and"
          }
        })
        maintenance_policy:access(ctx)
        assert.stub(ngx.exit).was_called_with(503)
      end)
    end)

    context('when Maintenance Mode is configured for a specific upstream (different host)', function()  
      it('does not enable maintenance mode', function()
        local maintenance_policy = MaintenancePolicy.new({
          condition = {
            operations = {{
              op="==", left="{{ upstream.host }}{{ upstream.path }}", 
              left_type="liquid", right=test_host2..test_path, right_type="plain"
            }},
            combine_op="and"
          }
        })
        maintenance_policy:access(ctx)
        assert.stub(ngx.say).was_not_called()
      end)
    end)

    context('when Maintenance Mode is configured for a specific upstream (different path)', function()  
      it('does not enable maintenance mode', function()
        local maintenance_policy = MaintenancePolicy.new({
          condition = {
            operations = {{
              op="==", left="{{ upstream.host }}{{ upstream.path }}", left_type="liquid", 
              right=test_host..test_path2, right_type="plain"
            }},
            combine_op="and"
          }
        })
        maintenance_policy:access(ctx)
        assert.stub(ngx.say).was_not_called()
      end)
    end)

    context('when Maintenance Mode is configured for a specific upstream (different scheme and port)', function()
      it('does not enable maintenance mode', function()  
        local maintenance_policy = MaintenancePolicy.new({
          condition = {
            operations = {{
              op="==", left="{{ upstream.scheme }}://{{ upstream.host }}{{ upstream.port }}{{ upstream.path }}", 
              left_type="liquid", right="http://"..test_host.."80"..test_path, right_type="plain", right_type="plain"
            }},
            combine_op="and"
          }
        })
        maintenance_policy:access(ctx)
        assert.stub(ngx.say).was_not_called()
      end)
    end)

    context('when host "matches"', function()
      it('returns 503', function()  
        local maintenance_policy = MaintenancePolicy.new({
          condition = {
           operations = {{
             op="matches", left=test_host..test_path, left_type="plain", right="{{ upstream.host }}" , 
             right_type="liquid"
            }},
           combine_op="and"
          }
        })
        maintenance_policy:access(ctx)
        assert.stub(ngx.exit).was_called_with(503)
      end)
    end)

    context('OR condition match one', function()
      it('returns 503', function()  
        local maintenance_policy = MaintenancePolicy.new({
          condition = {
            operations={
              {
                op="==", left="{{ upstream.host }}{{ upstream.path }}", left_type="liquid", 
                right=test_host2..test_path2, right_type="plain"
              },
              {
                op="==", left="{{ upstream.host }}{{ upstream.path }}", left_type="liquid", 
                right=test_host..test_path, right_type="plain"
              }
            },
            combine_op="or"
          }
        })
        maintenance_policy:access(ctx)
        assert.stub(ngx.exit).was_called_with(503)
      end)
    end)

    context('no match conditions', function()
      it('does not enable maintenance mode', function()  
        local maintenance_policy = MaintenancePolicy.new({
          condition = {
            operations={
              {
                op="==", left="{{ upstream.host }}{{ upstream.path }}", left_type="liquid", 
                right=test_host..test_path2, right_type="plain"
              },
              {
                op="==", left="{{ upstream.host }}{{ upstream.path }}", left_type="liquid", 
                right=test_host2..test_path, right_type="plain"
              }
            },
            combine_op="or"
          }
        })
        maintenance_policy:access(ctx)
        assert.stub(ngx.say).was_not_called()
      end)
    end)
  end)
end)


