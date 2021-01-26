local MaintenancePolicy = require('apicast.policy.maintenance_mode')
local ngx_variable = require('apicast.policy.ngx_variable')

describe('Maintenance mode policy', function()

  describe('.access', function()
    before_each(function()
      ctx = { service = { api_backend = 'http://backend2.example.org:80' } }
      ctx2 = {
        route_upstream = { uri = { host = "backend2.example.org" } },
        service = { api_backend = 'http://backend2.example.org:80' }
      }
      stub(ngx, 'say')
      stub(ngx, 'exit')
      ngx.header = {}
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

    context('when restricting to a list of backends including the current', function()
      local maintenance_policy = MaintenancePolicy.new(
        {
          upstreams = {
            { url = "backend1.example.org"},
            { url = "backend2.example.org"}
          }
        }
      )

      it('returns 503', function()
        maintenance_policy:access(ctx)
        assert.stub(ngx.exit).was_called_with(503)
      end)
    end)

    context('when restricting to a list of backends, not including the current', function()
      local maintenance_policy = MaintenancePolicy.new(
        {
          upstreams = {
            { url = "backend3.example.org"},
            { url = "backend4.example.org"}
          }
        }
      )

      it('returns nil', function()
        local ret = maintenance_policy:access(ctx)
        assert.is_nil(ret)
      end)
    end)

    context('when the upstream is updated by other policies', function()
      local maintenance_policy = MaintenancePolicy.new()

      it('returns 503', function()
        maintenance_policy:access(ctx2)
        assert.stub(ngx.exit).was_called_with(503)
      end)
    end)

    context('when the upstream is updated by other policies and it is not in the list', function()
      local maintenance_policy = MaintenancePolicy.new(
        {
          upstreams = {
            { url = "backend3.example.org"},
            { url = "backend4.example.org"}
          }
        }
      )

      it('returns nil', function()
        local ret = maintenance_policy:access(ctx2)
        assert.is_nil(ret)
      end)
    end)
  end)


  describe("Conditions", function()

    before_each(function()
      ctx = {
        service = { api_backend = 'http://backend2.example.org:80' },
        foo = 'fooValue' 
      }
      stub(ngx, 'say')
      stub(ngx, 'exit')
      ngx.header = {}
      stub(ngx_variable, 'available_context', function(context) return context end)
    end)

    it("only apply maintenance if matches", function()
      local maintenance_policy = MaintenancePolicy.new({
        condition = {
          operations={{op="==", match="{{ foo }}", match_type="liquid", value="fooValue", value_type="plain"}},
          combine_op="and"
        }})
      maintenance_policy:access(ctx)
      assert.stub(ngx.exit).was_called_with(503)
    end)

    it("Validate default combine_op", function()
      local maintenance_policy = MaintenancePolicy.new({
        condition = {
          operations={{op="==", match="{{ foo }}", match_type="liquid", value="fooValue", value_type="plain"}}
        }})
      maintenance_policy:access(ctx)
      assert.stub(ngx.exit).was_called_with(503)
    end)

    it("Or combination match one", function()
      local maintenance_policy = MaintenancePolicy.new({
        condition = {
          operations={
            {op="==", match="{{ invalid }}", match_type="liquid", value="fooValue", value_type="plain"},
            {op="==", match="{{ foo }}", match_type="liquid", value="fooValue", value_type="plain"}
          },
          combine_op="or"
        }})
      maintenance_policy:access(ctx)
      assert.stub(ngx.exit).was_called_with(503)
    end)

    it("No Match combination", function()
      local maintenance_policy = MaintenancePolicy.new({
        condition = {
          operations={{op="==", match="{{ invalid }}", match_type="liquid", value="fooValue", value_type="plain"}},
          combine_op="and"
        }})
      local ret = maintenance_policy:access(ctx)
      assert.is_nil(ret)
    end)
  end)
end)


