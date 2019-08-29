local loader = require 'apicast.configuration_loader.data_url'
local cjson = require('cjson')

describe('Configuration Data URL loader', function()
  describe('.call', function()
    it('ignores empty url', function()
      assert.same({nil, 'not valid data-url'}, { loader.call() })
      assert.same({nil, 'not valid data-url'}, { loader.call('') })
    end)

    local config = cjson.encode{
      services = {
        { id = 21 },
        { id = 42 },
      }
    }

    it('decodes urlencoded data url', function()
      local url = ([[data:application/json,%s]]):format(ngx.escape_uri(config))
      assert.same(config, loader.call(url))
    end)

    it('ignores charset in the data url', function()
      local url = ([[data:application/json;charset=iso8601,%s]]):format(ngx.escape_uri(config))
      assert.same(config, loader.call(url))
    end)

    it('decodes base64 encoded data url', function()
      local url = ([[data:application/json;base64,%s]]):format(ngx.encode_base64(config))
      assert.same(config, loader.call(url))
    end)

    it('requires application/json media type', function()
      local url = ([[data:text/json,%s]]):format(ngx.escape_uri(config))

      assert.same({nil, 'unsupported mediatype'}, { loader.call(url) })
    end)
  end)
end)
