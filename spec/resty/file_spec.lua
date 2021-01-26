local file_reader = require("resty.file").file_reader
local random = math.random

local function uuid()
    local template ='xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'
    return string.gsub(template, '[xy]', function (c)
        local v = (c == 'x') and random(0, 0xf) or random(8, 0xb)
        return string.format('%x', v)
    end)
end

describe('File utilities', function()
  local filename = "/tmp/" ..uuid() .. ".txt"

  before_each(function()
    local file = io.open(filename, 'w')
    local file_size = (2 ^ 10 * 16) -- 16kb
    for _=1,file_size do
      file:write("1")
    end
    file:close()
  end)

  it('file reader is using coroutines', function()
    local reader, err = file_reader(filename)
    assert.falsy(err)
    assert.same(type(reader), "function")
    assert.truthy(reader()) -- First 8 KB
    assert.truthy(reader()) -- Second 8 KB
    assert.falsy(reader()) -- Nothing to read, return nil
  end)

  it('file reader return error on invalid path', function()
    local reader, err = file_reader("my_invalid_path.txt")
    assert.falsy(reader)
    assert.truthy(err)
  end)

end)
