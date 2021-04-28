
local GC = require('apicast.policy.gc')

local shdict_mt = {
  __index = {
    flush_expired = function() return 1 end,
  }
}
local function shdict()
  return setmetatable({ }, shdict_mt)
end

describe('GC policy', function()

  it("Delete shared dict entries on timeout", function()

    local gc = GC.new(1)
    gc:init_worker()

    --- just to make sure that every is used and no mistake in the future
    for var=0,1 do
      ngx.shared.gc_test = shdict()
      spy.on(ngx.shared.gc_test, "flush_expired")
      ngx.sleep(1)
      assert.spy(ngx.shared.gc_test.flush_expired).was.called()
    end
  end)

end)
