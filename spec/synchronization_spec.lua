describe("Synchronization", function()
  local synchronization
  local key = "foo"

  before_each(function()
    synchronization = require('resty.synchronization').new(1)
  end)

  it("Valid run execution", function()
    local callback = spy.new(function() return 1 end)

    local ret, result = synchronization:run(key, 10, callback)
    assert.same(ret, true)
    assert.same(result, {1})
    assert.spy(callback).was.called()
  end)

  it("Validates that run send correctly the arguments", function()
    local callback = spy.new(function(k, v) return k, v end)

    local ret, result = synchronization:run(key, 4, callback, "bob", "alice")
    assert.same(ret, true)
    assert.same(result, {"bob", "alice"})
    assert.spy(callback).was_called()
  end)

  it("Validates that run does not break if a exception on the callback", function()
    local callback = spy.new(function()
      local data = {};
      return data[3]
    end)

    local ret, result = synchronization:run(key, 4, callback)
    assert.same(ret, true)
    assert.same(result, {})
    assert.spy(callback).was_called()
  end)

  it("Validates that run fails if key is locked and timeout", function()
    local callback = spy.new(function() return 1 end)

    local sema = synchronization:acquire(key)
    local ok, err = sema:wait(5)
    assert.same(ok, true)
    assert.same(err, nil)

    local ret, result = synchronization:run(key, 2, callback)
    assert.same(ret, false)
    assert.same(result, nil)
    assert.spy(callback).was_not_called()

    synchronization:release(key)
    sema:post()
  end)

  it("Validate that acquire fails if not initialize", function()
    local sync = require('resty.synchronization')
    local sema, err = sync:acquire(key)
    assert.same(sema, nil)
    assert.same(err, "not initialized")
  end)

  it("validate that acquire/release workflow", function()

    local sema, _ = synchronization:acquire(key)
    assert.is.not_nil(synchronization.semaphores[key])
    assert.is.not_nil(sema)

    local ok, err = sema:wait(15)
    assert.same(ok, true)
    assert.same(err, nil)

    ok, err = synchronization.release(key)
    assert.same(ok, nil)
    assert.is.not_nil(err, nil)
  end)

end)
