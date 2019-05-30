local busted = require('busted')
local assert = require('luassert.assert')
local spy = require('luassert.spy')
local stub = require('luassert.stub')
local util = require ('luassert.util')
local say = require('say')

-- The stub.new and spy.on functions are patched here to make sure that the
-- target function is not already a mocked function.
-- The main reason to do that is to avoid some test that a function is mocked
-- on  the before_each and after in the test also is mocked again, all mocks
-- are reverted(state.revert in this module), but if the mock is double, it is
-- only reverted once, so the first mock function will be leaked to other test.
local original_stub_new = stub.new
local original_spy_on = spy.on

function stub.new(object, key, ...)
  if object and spy.is_spy(object[key]) then
    error("Stub for key='".. key .."' is already a mocked function, revert the parent function")
  end
  return original_stub_new(object, key, ...)
end

function spy.on(object, key)
  if object and spy.is_spy(object[key]) then
    error("Spy for key='".. key .."' is already a mocked function, revert the parent function")
  end
  return original_spy_on(object, key)
end

do -- set up reverting stubs
  local state = require("luassert.state")

  local function snapshot()
    --- creates a snapshot and adds it to a stack
    state.snapshot()
    return nil, true -- to not stop the chain
  end

  local function revert()
    --- reverts state of the current snapshot and removes it from the stack
    state.revert()
    return nil, true
  end

  for _, phase in ipairs({ 'suite', 'file', 'describe', 'it'}) do
    busted.subscribe({ phase, 'start' }, snapshot)
    busted.subscribe({ phase, 'end' }, revert)
  end

  busted.before_each(snapshot)
  busted.after_each(revert)
end

do -- adding gt matcher: assert.spy(something).was_called_with(match.is_gt(4))
  local function is_gt(_, arguments)
    local expected = arguments[1]
    return function(value)
      return value > expected
    end
  end

  assert:register("matcher", "gt", is_gt)
end

do -- adding assert.returns_error(error_text, ok, ret) : assert.returns_error('not initialized', _M:call())
  local tostring = tostring
  local s = require('say')

  local function returns_error(state, arguments, level)
    local argc = arguments.n
    assert(argc >= 2, say("assertion.internal.argtolittle", { "error_matches", 2, tostring(argc) }), level)

    local expected = arguments[1]
    local ok = arguments[2]
    local actual = arguments[3]

    assert(expected, 'missing expected message')
    local result = not ok and expected == actual

    -- switch arguments for proper output message
    util.tinsert(arguments, 1, util.tremove(arguments, 3))
    state.failure_message = arguments[3]
    return result
  end

  assert:register("assertion", "returns_error", returns_error, "assertion.error.positive", "assertion.error.negative")

  local function contains_left(left, right)
    if left == right then
      return true
    elseif type(left) == 'table' then
      for k,v in pairs(left) do
        local same, crumbs = contains_left(v, right[k])

        if not same then
          crumbs = crumbs or { }
          table.insert(crumbs,  k)
          return false, crumbs
        end
      end

      return true
    else
      return false
    end
  end


  local function set_failure_message(state, message)
    if message ~= nil then
      state.failure_message = message
    end
  end

  local function contains(expected, actual)
    assert.is_table(expected)
    assert.is_table(actual)

    local result, _ = contains_left(expected, actual)

    return result
  end

  local function contains_assertion(state, arguments, level)
    local argcnt = arguments.n

    assert(argcnt > 1, s("assertion.internal.argtolittle", { "same", 2, tostring(argcnt) }), (level or 1) + 1)

    local result, crumbs = contains(arguments[1], arguments[2])
    util.tinsert(arguments, 1, util.tremove(arguments, 2))
    arguments.fmtargs = arguments.fmtargs or {}
    arguments.fmtargs[1] = { crumbs = crumbs }
    arguments.fmtargs[2] = { crumbs = crumbs }
    set_failure_message(state, arguments[3])

    return result
  end

  local function contains_matcher(_, arguments, level)
    local argcnt = arguments.n

    assert(argcnt == 1, s("assertion.internal.argtolittle", { "same", 1, tostring(argcnt) }), (level or 1) + 1)
    local expected = arguments[1]

    return function(actual)
      return contains(expected, actual)
    end
  end

  s:set("assertion.contains.positive", "Expected object to contain another.\nPassed in:\n%s\nExpected:\n%s")
  s:set("assertion.contains.negative", "Expected objects to not contain another.\nPassed in:\n%s\nDid not expect:\n%s")

  assert:register("assertion", "contains", contains_assertion, "assertion.contains.positive", "assertion.contains.negative")
  assert:register("matcher", "contains", contains_matcher)

  assert.has_error(function()
    assert.returns_error('failure', true, 'wrong')
  end)
end
