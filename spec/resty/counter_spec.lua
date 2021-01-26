local counter = require "resty.counter"

describe("value object", function()

  describe("increment", function()
      it("delta default value is 1", function()
        local val = counter.new(0)
        assert.same(val:increment(), 1)
      end)

      it("with delta", function()
        local val = counter.new(0)
        assert.same(val:increment(10), 10)
      end)

      it("with invalid delta", function()
        local val = counter.new(0)
        assert.same(val:increment("foo"), 1)
      end)
  end)

  describe("decrement", function()
      it("default value is 1", function()
        local val = counter.new(0)
        assert.same(val:decrement(), -1)
      end)

      it("with delta", function()
        local val = counter.new(10)
        assert.same(val:decrement(10), 0)
      end)

      it("with invalid delta", function()
        local val = counter.new(0)
        assert.same(val:decrement("foo"), -1)
      end)
  end)


  describe("decrement", function()
      it("is not a number", function()
        local val = counter.new("foo")
        assert.same(val:decrement(), -1)
      end)

      it("is negative", function()
        local val = counter.new(-1)
        assert.same(val:decrement(), -2)
      end)

      it("Tostring return the value", function()
        local val = counter.new(-1)
        assert.same(val:__tostring(), "-1")
      end)

  end)

end)
