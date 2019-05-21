local _M = require 'resty.yaml'

describe('Resty YAML', function()
  describe('.load', function()
    it('loads yaml', function()
      assert.same({ global = _M.null }, _M.load('global: '))
    end)
  end)

  describe('.null', function()
    it('is ngx.null', function ()
      assert.equal(ngx.null, _M.null)
    end)
  end)
end)
