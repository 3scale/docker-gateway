local rate_limit_condition = require('apicast.policy.rate_limit.rate_limit_condition')

describe('Rate Limit Condition', function()

  describe('errors', function()
    it('condition error', function()
      local result, err = rate_limit_condition.evaluate("aaa", {})
      assert.falsy(result)
      assert.equal("Condition is missing.", err)
    end)

    it('combination error', function()
      local options = { conditions = { {}, {} } }
      local result, err = rate_limit_condition.evaluate("aaa", options)
      assert.falsy(result)
      assert.equal("Combination is missing.", err)
    end)

    it('key is not number', function()
      local options = { conditions = { { operator = "greater_than", value = 0 } } }
      local result, err = rate_limit_condition.evaluate("aaa", options)
      assert.falsy(result)
      assert.equal("aaa is not number.", err)
    end)

    it('value is not number', function()
      local options = { conditions = { { operator = "greater_than", value = "aaa" } } }
      local result, err = rate_limit_condition.evaluate(0, options)
      assert.falsy(result)
      assert.equal("aaa is not number.", err)
    end)
  end)

  describe('equals', function()
    it('true', function()
      local options = { conditions = { { operator = "equals", value = "aaa" } } }
      assert(rate_limit_condition.evaluate("aaa", options))
    end)

    it('false', function()
      local options = { conditions = { { operator = "equals", value = "bbb" } } }
      assert.falsy(rate_limit_condition.evaluate("aaa", options))
    end)
  end)

  describe('not equals', function()
    it('true', function()
      local options = { conditions = { { operator = "not_equals", value = "bbb" } } }
      assert(rate_limit_condition.evaluate("aaa", options))
    end)

    it('false', function()
      local options = { conditions = { { operator = "not_equals", value = "aaa" } } }
      assert.falsy(rate_limit_condition.evaluate("aaa", options))
    end)
  end)

  describe('contains', function()
    it('true', function()
      local options = { conditions = { { operator = "contains", value = "aa" } } }
      assert(rate_limit_condition.evaluate("aaa", options))
    end)

    it('false', function()
      local options = { conditions = { { operator = "contains", value = "aaaa" } } }
      assert.falsy(rate_limit_condition.evaluate("aaa", options))
    end)

    it('true table', function()
      local options = { conditions = { { operator = "contains", value = "bbb" } } }
      assert(rate_limit_condition.evaluate({"aaa", "bbb"}, options))
    end)

    it('false table', function()
      local options = { conditions = { { operator = "contains", value = "aa" } } }
      assert.falsy(rate_limit_condition.evaluate({"aaa", "bbb"}, options))
    end)
  end)

  describe('not contains', function()
    it('true', function()
      local options = { conditions = { { operator = "not_contains", value = "aaaa" } } }
      assert(rate_limit_condition.evaluate("aaa", options))
    end)

    it('false', function()
      local options = { conditions = { { operator = "not_contains", value = "aa" } } }
      assert.falsy(rate_limit_condition.evaluate("aaa", options))
    end)

    it('true table', function()
      local options = { conditions = { { operator = "not_contains", value = "aa" } } }
      assert(rate_limit_condition.evaluate({"aaa", "bbb"}, options))
    end)

    it('false table', function()
      local options = { conditions = { { operator = "not_contains", value = "bbb" } } }
      assert.falsy(rate_limit_condition.evaluate({"aaa", "bbb"}, options))
    end)
  end)

  describe('greater than', function()
    it('true', function()
      local options = { conditions = { { operator = "greater_than", value = 0 } } }
      assert(rate_limit_condition.evaluate(1, options))
    end)

    it('false', function()
      local options = { conditions = { { operator = "greater_than", value = 1 } } }
      assert.falsy(rate_limit_condition.evaluate(1, options))
    end)
  end)

  describe('greater than or equals', function()
    it('true', function()
      local options = { conditions = { { operator = "greater_than_or_equals", value = 1 } } }
      assert(rate_limit_condition.evaluate(1, options))
    end)

    it('false', function()
      local options = { conditions = { { operator = "greater_than_or_equals", value = 2 } } }
      assert.falsy(rate_limit_condition.evaluate(1, options))
    end)
  end)

  describe('less than', function()
    it('true', function()
      local options = { conditions = { { operator = "less_than", value = 0 } } }
      assert(rate_limit_condition.evaluate(-1, options))
    end)

    it('false', function()
      local options = { conditions = { { operator = "less_than", value = -1 } } }
      assert.falsy(rate_limit_condition.evaluate(-1, options))
    end)
  end)

  describe('less than or equals', function()
    it('true', function()
      local options = { conditions = { { operator = "less_than_or_equals", value = -1 } } }
      assert(rate_limit_condition.evaluate(-1, options))
    end)

    it('false', function()
      local options = { conditions = { { operator = "less_than_or_equals", value = -2 } } }
      assert.falsy(rate_limit_condition.evaluate(-1, options))
    end)
  end)

  describe('and', function()
    it('true', function()
      local options = {
        conditions = {
          { operator = "less_than", value = 0 },
          { operator = "greater_than", value = -2 }
        },
        conditions_combination = "and"
      }
      assert(rate_limit_condition.evaluate(-1, options))
    end)

    it('false', function()
      local options = {
        conditions = {
          { operator = "less_than", value = 0 },
          { operator = "greater_than", value = -1 }
        },
        conditions_combination = "and"
      }
      assert.falsy(rate_limit_condition.evaluate(-1, options))
    end)
  end)

  describe('or', function()
    it('true', function()
      local options = {
        conditions = {
          { operator = "less_than", value = -1 },
          { operator = "greater_than", value = -2 }
        },
        conditions_combination = "or"
      }
      assert(rate_limit_condition.evaluate(-1, options))
    end)

    it('false', function()
      local options = {
        conditions = {
          { operator = "less_than", value = -1 },
          { operator = "greater_than", value = -1 }
        },
        conditions_combination = "or"
      }
      assert.falsy(rate_limit_condition.evaluate(-1, options))
    end)
  end)

end)
