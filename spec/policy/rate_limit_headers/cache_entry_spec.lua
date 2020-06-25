local Usage = require('apicast.usage')


describe("Cache key", function()
  local usage
  local cache_entry

  before_each(function()
    usage = Usage.new()
    usage:add("a", 3)
    stub(ngx, 'now', function() return 100 end)
    -- Imported here to be able to use stub ngx.now()
    cache_entry = require("apicast.policy.rate_limit_headers.cache_entry")
  end)

  it("New works as expected", function()
    local key = cache_entry.new(usage, 1, 2, 3)
    assert.same(key.limit:__tostring(), "1")
    assert.same(key.remaining:__tostring(), "2")
    assert.True(key.reset.limit_time > 0)
  end)

  it("decrements works as expected", function()

    local key = cache_entry.new(usage, 1, 10, 3)
    key:decrement(1)
    assert.same(key.remaining:__tostring(), "9")

    key:decrement(10)
    assert.same(key.remaining:__tostring(), "-1")
  end)

  describe("Import/export methods",  function()

    it("Works as expected", function()

      local entry = cache_entry.new(usage, 1, 10, 3)
      assert.same(entry:export(), "1#10#3")
      local data = cache_entry.import(usage, entry:export())
      assert.same(data.limit:__tostring(), "1")
      assert.same(data.remaining:__tostring(), "10")
      assert.same(data.reset:__tostring(), "103")
    end)


    it("invalid usage returns nil", function()
      assert.falsy(cache_entry.import())
    end)

    it("invalid import raw data", function()
      local data = cache_entry.import(usage, "1#asd#123")
      assert.same(data.limit:__tostring(), "1")
      assert.same(data.remaining:__tostring(), "0")
      assert.same(data.reset:__tostring(), "223")
    end)

    it("no raw_data return empty data", function()
      local data = cache_entry.import(usage, "")
      assert.same(data.limit:__tostring(), "0")
      assert.same(data.remaining:__tostring(), "0")
      assert.same(data.reset:__tostring(), "100")
    end)

  end)

end)
