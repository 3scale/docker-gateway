local Usage = require('apicast.usage') local cache = require("apicast.policy.rate_limit_headers.cache")
describe("Cache key", function()
  local usage

  before_each(function()
    usage = Usage.new()
    usage:add("a", 3)
  end)

  it("New works as expected", function()
    local c = cache.new("namespace")
    assert.Same(c.namespace, "namespace")
    assert.is_not(c.cache, nil)

    assert.Same(c:get_key(usage), "namespace::usage%5Ba%5D=3")
  end)

  it("Decrement when no usage was before in there", function()
    local c = cache.new("namespace")
    local entry = c:decrement_usage_metric(nil):dump_data()
    assert.Same(entry.limit, "0")
    assert.Same(entry.remaining, "0")

    entry = c:decrement_usage_metric(usage):dump_data()
    assert.Same(entry.limit, "0")
    assert.Same(entry.remaining, "0")
  end)

  it("Decrement works as expected", function()
    local c = cache.new("namespace")
    c:reset_or_create_usage_metric(usage, 10, 10, 10)

    local entry = c:decrement_usage_metric(usage):dump_data()

    assert.Same(entry.limit, "10")
    assert.Same(entry.remaining, "9")
  end)

  it("Decrement with multiple usages use max hits", function()

    usage = Usage.new()
    usage:add("a", 1)
    usage:add("j", 5)
    usage:add("b", 2)

    local c = cache.new("namespace")
    c:reset_or_create_usage_metric(usage, 10, 10, 10)

    local entry = c:decrement_usage_metric(usage):dump_data()

    assert.Same(entry.limit, "10")
    assert.Same(entry.remaining, "9")
  end)
end)
