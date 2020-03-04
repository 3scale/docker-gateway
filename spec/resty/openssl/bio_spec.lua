local _M = require('resty.openssl.bio')

describe('OpenSSL BIO', function()
  describe('.new', function()
    it('returns cdata', function()
      assert.equal('cdata', type(_M.new()))
    end)
  end)

  describe(':write', function()
    it('writes data to bio', function()
      local bio = _M.new()
      local str = 'foobar'

      assert(bio:write(str))
      assert.equal(str, bio:read())
    end)

    it('requires a string', function()
      local bio = _M.new()

      assert.has_error(function () bio:write() end, 'expected string')
    end)

    it('empty string return 0', function()
      local bio = _M.new()
      assert.same(bio:write(""), 0)
    end)
  end)

end)
