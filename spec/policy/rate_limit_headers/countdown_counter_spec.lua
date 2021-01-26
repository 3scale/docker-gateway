
local countdown = require("apicast.policy.rate_limit_headers.countdown_counter")

describe("Countdown counter", function()
  describe("remainging secs", function()
    it("it works correctly", function()
      local count = countdown.new(10, 0)

      assert.equals(count:remaining_secs(10), 0)
      assert.equals(count:remaining_secs(5), 5)
    end)

    it("with negatives arg", function()
      local count = countdown.new(10, 0)

      assert.equals(count:remaining_secs(-10), 20)
      assert.equals(count:remaining_secs(-5), 15)
    end)

    it("out of the limits", function()
      local count = countdown.new(10, 0)
      assert.equals(count:remaining_secs(11), -1)
    end)
  end)

  describe("remainging secs positive", function()
    it("it works correctly", function()
      local count = countdown.new(10, 0)

      assert.equals(count:remaining_secs_positive(10), 0)
      assert.equals(count:remaining_secs_positive(5), 5)

    end)

    it("with negatives arg", function()
      local count = countdown.new(10, 0)

      assert.equals(count:remaining_secs_positive(-10), 20)
      assert.equals(count:remaining_secs_positive(-5), 15)
    end)

    it("out of the limits", function()
      local count = countdown.new(10, 0)
      assert.equals(count:remaining_secs_positive(11), 0)
    end)

    it("with no integers numbers", function()
      local count = countdown.new(10, 0)
      assert.equals(count:remaining_secs_positive(1.1), 8)
    end)

  end)

end)
