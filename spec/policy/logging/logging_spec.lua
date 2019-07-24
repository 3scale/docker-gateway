local LoggingPolicy = require('apicast.policy.logging')
local ngx_variable = require('apicast.policy.ngx_variable')
local cjson = require('cjson')

describe('Logging policy', function()

  local function access_logs_are_enabled()
    return ngx.var.access_logs_enabled == '1'
  end

  describe('.log', function()
    before_each(function()
      ngx.var = {}
    end)

    context('when access logs are enabled', function()
      it('sets ngx.var.access_logs_enabled to "1"', function()
        local logging = LoggingPolicy.new({ enable_access_logs = true })

        logging:log()
        assert.is_true(access_logs_are_enabled())
      end)
    end)

    context('when access logs are disabled', function()
      it('sets ngx.var.enable_access_logs to "0"', function()
        local logging = LoggingPolicy.new({ enable_access_logs = false })

        logging:log()
        assert.falsy(access_logs_are_enabled())
      end)
    end)

    context('when access logs are not configured', function()
      it('enables them by default by setting ngx.var.enable_access_logs to "1"', function()
        local logging = LoggingPolicy.new({})

        logging:log()

        assert.equals('1', ngx.var.access_logs_enabled)
      end)
    end)
  end)

  describe("Extended log", function()
    local ctx = { service = { id = 123 } }

    local function extended_logs_are_correctly_enabled()
      assert.falsy(access_logs_are_enabled())
      assert.equals(1, ngx.var.extended_access_logs_enabled)
    end

    before_each(function()
      ngx.var = {foo = "fooValue"}
      stub(ngx.req, 'get_headers', function() return { bar="barValue" } end)
      stub(ngx.resp, 'get_headers', function() return { foo="fooValue" } end)
      stub(ngx_variable, 'available_context', function(context) return context end)
    end)

    it("Default access log is disabled when is defined", function()
      local logging = LoggingPolicy.new({custom_logging="foo"})
      logging:log(ctx)

      extended_logs_are_correctly_enabled()
      assert.equals("foo", ngx.var.extended_access_log)
    end)

    it("log message render information from context and ngx.var", function()

      local logging = LoggingPolicy.new({
        custom_logging=">>{{foo}}::{{service.id}}"
      })
      logging:log(ctx)
      extended_logs_are_correctly_enabled()
      assert.equals(">>fooValue::123", ngx.var.extended_access_log)
    end)

    it("log message render response and request headers", function()
      local logging = LoggingPolicy.new({
        custom_logging=">>{{resp.headers.foo}}::{{req.headers.bar}}"
      })
      logging:log(ctx)
      extended_logs_are_correctly_enabled()
      assert.equals(">>fooValue::barValue", ngx.var.extended_access_log)
    end)

    describe("Conditions", function()

      it("Conditions only log if matches", function()
        local logging = LoggingPolicy.new({
          custom_logging = "foo",
          condition = {
            operations={{op="==", match="{{ foo }}", match_type="liquid", value="fooValue", value_type="plain"}},
            combine_op="and"
          }})
        logging:log(ctx)
        extended_logs_are_correctly_enabled()
        assert.equals("foo", ngx.var.extended_access_log)
      end)

      it("Validate default combine_op", function()
        local logging = LoggingPolicy.new({
          custom_logging = "foo",
          condition = {
            operations={{op="==", match="{{ foo }}", match_type="liquid", value="fooValue", value_type="plain"}}
          }})
        logging:log(ctx)
        extended_logs_are_correctly_enabled()
        assert.equals("foo", ngx.var.extended_access_log)
      end)

      it("Or combination match one", function()
        local logging = LoggingPolicy.new({
          custom_logging = "foo",
          condition = {
            operations={
              {op="==", match="{{ invalid }}", match_type="liquid", value="fooValue", value_type="plain"},
              {op="==", match="{{ foo }}", match_type="liquid", value="fooValue", value_type="plain"}
            },
            combine_op="or"
          }})
        logging:log(ctx)
        extended_logs_are_correctly_enabled()
        assert.equals("foo", ngx.var.extended_access_log)
      end)

      it("No Match combination", function()
        local logging = LoggingPolicy.new({
          custom_logging = "foo",
          condition = {
            operations={{op="==", match="{{ invalid }}", match_type="liquid", value="fooValue", value_type="plain"}},
            combine_op="and"
          }})
        logging:log(ctx)
        assert.falsy(access_logs_are_enabled())
        assert.equals(0, ngx.var.extended_access_logs_enabled)
        assert.is_nil(ngx.var.extended_access_log)
      end)

      describe("JSON Logs", function()

        local expected_json = cjson.encode({foo="fooValue", bar="barValue"})

        it("valid config", function()
          local logging = LoggingPolicy.new({
            enable_json_logs = true,
            json_object_config = {
              { key = "foo", value="{{foo}}", value_type="liquid"},
              { key = "bar", value="{{req.headers.bar}}", value_type="liquid"},
            }
          })
          logging:log(ctx)

          extended_logs_are_correctly_enabled()
          assert.equals(ngx.var.extended_access_log, expected_json)
        end)

        it("It is disabled by default", function()
          local logging = LoggingPolicy.new({
            custom_logging = "foo",
          })
          logging:log(ctx)

          extended_logs_are_correctly_enabled()
          assert.equals(ngx.var.extended_access_log, "foo")
        end)


        it("empty config logs empty json object", function()
          local logging = LoggingPolicy.new({
            enable_json_logs = true
          })
          logging:log(ctx)

          extended_logs_are_correctly_enabled()
          assert.equals(ngx.var.extended_access_log, '{}')
        end)


        it("render correctly liquid and plain entries", function()
          local logging = LoggingPolicy.new({
            enable_json_logs = true,
            json_object_config = {
              { key = "foo", value="{{foo}}", value_type="liquid"},
              { key = "bar", value="barValue", value_type="plain"},
            }
          })
          logging:log(ctx)

          extended_logs_are_correctly_enabled()
          assert.equals(ngx.var.extended_access_log, expected_json)
        end)

        it("Duplicated keys only render the last one", function()
          local logging = LoggingPolicy.new({
            enable_json_logs = true,
            json_object_config = {
              { key = "foo", value="{{foo}}", value_type="liquid"},
              { key = "bar", value="barValue", value_type="liquid"},
              { key = "bar", value="{{req.headers.bar}}", value_type="liquid"},
            }
          })
          logging:log(ctx)

          assert.falsy(access_logs_are_enabled())
          assert.equals(ngx.var.extended_access_log, expected_json)
        end)
      end)
    end)

  end)
end)
