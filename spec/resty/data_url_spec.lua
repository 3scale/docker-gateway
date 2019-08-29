local _M = require 'resty.data_url'
local MimeType = require 'resty.mime'

local application_json = MimeType.new('application/json')

describe('Data URL parser', function()
  describe('.parse', function()
    local parse = _M.parse
    local config = '{}'

    it('decodes urlencoded data url', function()
      local url = ([[data:application/json,%s]]):format(ngx.escape_uri(config))

      assert.same({
        base64 = false,
        data = '{}',
        mime_type = application_json,
      }, parse(url))
    end)

    it('ignores charset in the data url', function()
      local url = ([[data:application/json;charset=iso8601,%s]]):format(ngx.escape_uri(config))
      assert.same({
        base64 = false,
        data = '{}',
        mime_type = application_json,
      }, parse(url))
    end)

    it('decodes base64 encoded data url', function()
      local url = ([[data:application/json;base64,%s]]):format(ngx.encode_base64(config))
      assert.same({
        base64 = true,
        data = '{}',
        mime_type = application_json,
      }, parse(url))
    end)

    it('requires application/json media type', function()
      local url = ([[data:;name=config.json,%s]]):format(ngx.escape_uri(config))

      assert.same({
        base64 = false,
        data = '{}',
        mime_type = MimeType.new(),
      }, parse(url))
    end)
  end)
end)
