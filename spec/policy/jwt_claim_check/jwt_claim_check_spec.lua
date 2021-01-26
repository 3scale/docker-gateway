local JWTClaimCheckPolicy = require('apicast.policy.jwt_claim_check')
local ngx_variable = require('apicast.policy.ngx_variable')


describe('JWT claim check policy', function()

  local context = {
    jwt = {
      foo = "fooValue",
      one = "1",
      hundred= "100",
      ooo = { 1,2},
      roles = { "one", "two"}

    },
    get_uri = function()
      return ngx.var.uri
    end
  }

  before_each(function()
    ngx.header = {}
    stub(ngx, 'print')

    stub(ngx, 'say')

    stub(ngx.req, 'get_method', function() return 'GET' end)
    -- avoid stubbing all the ngx.var.* and ngx.req.* in the available context
    stub(ngx_variable, 'available_context', function(ctx) return ctx end)

    ngx.var = { uri = "/bbb" }
  end)

  describe("operations", function()
    describe("plain JWT_claim_type", function()
      it("valid claim", function()
        local jwt_check = JWTClaimCheckPolicy.new({rules={
          {
            operations={{op="==", jwt_claim="foo", jwt_claim_type="plain", value="fooValue"}},
            combine_op="and",
            methods  = {"GET"},
            resource = ngx.var.uri
          }
        }})
        jwt_check:access(context)
        assert.not_same(ngx.status, 403)
      end)

      it("invalid claim", function()
        local jwt_check = JWTClaimCheckPolicy.new({rules={
          {
            operations={{op="==", jwt_claim="invalid", jwt_claim_type="plain", value="fooValue"}},
            combine_op="and",
            methods  = {"GET"},
            resource = ngx.var.uri
          }
        }})
        jwt_check:access(context)
        assert.same(ngx.status, 403)
      end)
    end)

    describe("liquid JWT_claim_type", function()
      it("valid claim", function()
        local jwt_check = JWTClaimCheckPolicy.new({rules={
          {
            operations={{op="==", jwt_claim="{{foo}}", jwt_claim_type="liquid", value="fooValue"}},
            combine_op="and",
            methods  = {"GET"},
            resource = ngx.var.uri
          }
        }})
        jwt_check:access(context)
        assert.not_same(ngx.status, 403)
      end)

      it("invalid claim", function()
        local jwt_check = JWTClaimCheckPolicy.new({rules={
          {
            operations={{op="==", jwt_claim="{{invalid}}", jwt_claim_type="plain", value="fooValue"}},
            combine_op="and",
            methods  = {"GET"},
            resource = ngx.var.uri
          }
        }})
        jwt_check:access(context)
        assert.same(ngx.status, 403)
      end)
    end)

    describe("Liquid value type", function()

      it("valid value type", function()
        local jwt_check = JWTClaimCheckPolicy.new({rules={
          {
            operations={{op="==", jwt_claim="{{foo}}", jwt_claim_type="liquid", value="{{foo}}", value_type="liquid"}},
            combine_op="and",
            methods  = {"GET"},
            resource = ngx.var.uri
          }
        }})
        jwt_check:access(context)
        assert.not_same(ngx.status, 403)
      end)

      it("invalid value type", function()
        local jwt_check = JWTClaimCheckPolicy.new({rules={
          {
            operations={{op="==", jwt_claim="{{foo}}", jwt_claim_type="liquid", value="{{one}}", value_type="liquid"}},
            combine_op="and",
            methods  = {"GET"},
            resource = ngx.var.uri
          }
        }})
        jwt_check:access(context)
        assert.same(ngx.status, 403)
      end)
    end)

    describe("Conditions combinations", function()

      it("valid and combinations", function()
        local jwt_check = JWTClaimCheckPolicy.new({rules={
          {
            operations={
              {
                op="==", jwt_claim="{{foo}}", jwt_claim_type="liquid",
                value="fooValue"
              },{
                op="==", jwt_claim="{{roles|first}}", jwt_claim_type="liquid",
                value="one"
              }},
            combine_op="and",
            methods  = {"GET"},
            resource = ngx.var.uri
          }
        }})
        jwt_check:access(context)
        assert.not_same(ngx.status, 403)
      end)

      it("invalid and combinations", function()
          local jwt_check = JWTClaimCheckPolicy.new({rules={
          {
            operations={
              {
                op="==", jwt_claim="{{foo}}", jwt_claim_type="liquid",
                value="fooValue"
              },{
                op="!=", jwt_claim="{{roles|first}}", jwt_claim_type="liquid",
                value="one"
              }},
            combine_op="and",
            methods  = {"GET"},
            resource = ngx.var.uri
          }
        }})
        jwt_check:access(context)
        assert.same(ngx.status, 403)
      end)

      it("valid or combinations", function()
        local jwt_check = JWTClaimCheckPolicy.new({rules={
          {
            operations={
              {
                op="==", jwt_claim="{{foo}}", jwt_claim_type="liquid",
                value="fooValue"
              },{
                op="!=", jwt_claim="{{roles|first}}", jwt_claim_type="liquid",
                value="one"
              }},
            combine_op="or",
            methods  = {"GET"},
            resource = ngx.var.uri
          }
        }})
        jwt_check:access(context)
        assert.not_same(ngx.status, 403)
      end)

      it("invalid or combinations", function()
          local jwt_check = JWTClaimCheckPolicy.new({rules={
          {
            operations={
              {
                op="!=", jwt_claim="{{foo}}", jwt_claim_type="liquid",
                value="fooValue"
              },{
                op="!=", jwt_claim="{{roles|first}}", jwt_claim_type="liquid",
                value="one"
              }},
            combine_op="or",
            methods  = {"GET"},
            resource = ngx.var.uri
          }
        }})
        jwt_check:access(context)
        assert.same(ngx.status, 403)
      end)

    end)

  end)

  describe("validate methods entry", function()
    it("Invalid method with valid operations", function()
      local jwt_check = JWTClaimCheckPolicy.new({rules={
          {
            operations={{op="==", jwt_claim="{{foo}}", jwt_claim_type="liquid", value="fooValue"}},
            combine_op="and",
            methods  = {"POST"},
            resource = ngx.var.uri
          }
        }})
        jwt_check:access(context)
        assert.not_same(ngx.status, 403)
    end)

    it("ANY method with valid operations", function()
      local jwt_check = JWTClaimCheckPolicy.new({rules={
          {
            operations={{op="==", jwt_claim="{{foo}}", jwt_claim_type="liquid", value="fooValue"}},
            combine_op="and",
            methods  = {"ANY"},
            resource = ngx.var.uri
          }
        }})
        jwt_check:access(context)
        assert.not_same(ngx.status, 403)
    end)

    it("ANY method with no matching JWT role operations", function()
      local jwt_check = JWTClaimCheckPolicy.new({rules={
          {
            operations={{op="==", jwt_claim="{{ foo }}", jwt_claim_type="liquid", value="bar"}},
            combine_op="and",
            methods  = {"ANY"},
            resource = ngx.var.uri
          }
        }})
        jwt_check:access(context)
        assert.same(ngx.status, 403)
    end)

    it("Multiple methods with matching JWT role operations", function()
      local jwt_check = JWTClaimCheckPolicy.new({rules={
          {
            operations={{op="==", jwt_claim="{{ foo }}", jwt_claim_type="liquid", value="fooValue"}},
            combine_op="and",
            methods  = {"POST", "GET"},
            resource = ngx.var.uri
          }
        }})
        jwt_check:access(context)
        assert.not_same(ngx.status, 403)

        ngx.req.get_method:revert()
        stub(ngx.req, 'get_method', function() return 'POST' end)
        jwt_check:access(context)
        assert.not_same(ngx.status, 403)

        -- PUT method is not part of the rule, so it's allowed.
        ngx.req.get_method:revert()
        stub(ngx.req, 'get_method', function() return 'PUT' end)
        jwt_check:access(context)
        assert.not_same(ngx.status, 403)
    end)

  end)

  it("validates custom error message", function()
      local message = "custom one"
      local jwt_check = JWTClaimCheckPolicy.new({
        rules={
          {
            operations={{op="!=", jwt_claim="{{ foo }}", jwt_claim_type="liquid", value="fooValue"}},
            combine_op="and",
            methods  = {"POST", "GET"},
            resource = ngx.var.uri
          }
        },
        error_message=message})
      jwt_check:access(context)
      assert.same(ngx.status, 403)
      assert.stub(ngx.say).was.called()
      assert.stub(ngx.say).was.called_with(message)
  end)

end)
