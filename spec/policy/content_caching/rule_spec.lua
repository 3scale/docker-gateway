local caching_rule =  require("apicast.policy.content_caching.rule")
local ngx_variable = require 'apicast.policy.ngx_variable'

describe('Content Caching rule', function()
  local context = {}

  before_each(function()
    ngx.var = {}
    ngx.header = {}
    context = {
      foo = "foobar",
      bar = "barfoo"
    }
    stub(ngx_variable, 'available_context', function(ctx) return ctx end)
  end)

  describe("Plaintext test", function()
    it("default", function()
      local config = {
        cache = true,
        header = nil,
        condition = {
          combine_op = "and",
          operations = {
            { left = "bar", op = "==", right = "bar" }
          }
        }
      }

      local rule = caching_rule.new_from_config_rule(config)
      assert.is_true(rule.condition:evaluate(context))
    end)

    it("plaintext does not match", function()
      local config = {
        cache = true,
        header = nil,
        condition = {
          combine_op = "and",
          operations = {
            { left = "bar", op = "==", right = "foobar" }
          }
        }
      }

      local rule = caching_rule.new_from_config_rule(config)
      assert.is_falsy(rule.condition:evaluate(context))
    end)
  end)

  describe("liquid test", function()

    it("left_type", function()
      local config = {
        cache = true,
        header = nil,
        condition = {
          combine_op = "and",
          operations = {
            { left = "{{foo}}", left_type = "liquid", op = "==", right = "foobar" }
          }
        }
      }

      local rule = caching_rule.new_from_config_rule(config)
      assert.is_true(rule.condition:evaluate(context))
    end)

    it("right_type", function()
      local config = {
        cache = true,
        header = nil,
        condition = {
          combine_op = "and",
          operations = {
            { left = "barfoo", op = "==", right = "{{bar}}", right_type = "liquid" }
          }
        }
      }

      local rule = caching_rule.new_from_config_rule(config)
      assert.is_true(rule.condition:evaluate(context))
    end)
  end)
end)
