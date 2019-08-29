local _M = require 'resty.mime'

describe('Resty MimeType', function()

  describe('.new', function()
    it('extracts media_type', function()
      local mime = _M.new('application/json+test;charset=utf-8;param=value;quoted="value"')

      assert.same('application/json+test', mime.media_type)
    end)

    it('normalizes media_type', function()
      local mime = _M.new('Application/JSON+test')
      assert.same('application/json+test', mime.media_type)
    end)

    it('extracts parameters', function()
      local mime = _M.new('application/json+test;charset=utf-8;param=value;quoted="value"')

      assert.same([[charset=utf-8;param=value;quoted="value"]], mime.parameters)
    end)

    it('returns empty on false', function()
      local mime = _M.new(false)

      assert.is_nil(mime.media_type)
      assert.is_nil(mime.parameters)
    end)

    it('returns empty on nil', function()
      local mime = _M.new(nil)

      assert.is_nil(mime.media_type)
      assert.is_nil(mime.parameters)
    end)
  end)

  describe(':parameter(name)', function()
    it('extracts unquoted parameters', function()
      local mime = _M.new('application/json+test; charset=utf-8 ;param=val; quoted="value"')

      assert.same('utf-8', mime:parameter('charset'))
      assert.same('val', mime:parameter('param'))
    end)

    it('extracts quoted parameters', function()
      local mime = _M.new('application/json+test; charset=utf-8 ;param=val; quoted="value"; other="some"')

      assert.same('value', mime:parameter('quoted'))
      assert.same('some', mime:parameter('other'))
    end)
  end)
end)
