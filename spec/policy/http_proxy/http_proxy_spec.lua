local proxy_policy = require('apicast.policy.http_proxy')
local resty_url = require 'resty.url'

describe('HTTP proxy  policy', function()
  local all_proxy_val = "http://all.com"
  local http_proxy_val = "http://plain.com"
  local https_proxy_val = "http://secure.com"

  local http_uri = {scheme="http"}
  local https_uri = {scheme="https"}

  it("http[s] proxies are defined if all_proxy is in there", function()
    local proxy = proxy_policy.new({
      all_proxy = all_proxy_val
    })
    local callback = proxy:export()

    assert.same(callback.get_http_proxy(http_uri), resty_url.parse(all_proxy_val))
    assert.same(callback.get_http_proxy(https_uri), resty_url.parse(all_proxy_val))
  end)

  it("all_proxy does not overwrite http/https proxies", function()
    local proxy = proxy_policy.new({
      all_proxy = all_proxy_val,
      http_proxy = http_proxy_val,
      https_proxy = https_proxy_val
    })
    local callback = proxy:export()

    assert.same(callback.get_http_proxy(http_uri), resty_url.parse(http_proxy_val))
    assert.same(callback.get_http_proxy(https_uri), resty_url.parse(https_proxy_val))
  end)

  it("empty config return all nil", function()
    local proxy = proxy_policy.new({})
    local callback = proxy:export()

    assert.is_nil(callback.get_http_proxy(https_uri))
    assert.is_nil(callback.get_http_proxy(http_uri))
  end)

  describe("get_http_proxy callback", function()
    local callback = proxy_policy.new({
        all_proxy = all_proxy_val
    }):export()

    it("Valid protocol", function()

      local result = callback.get_http_proxy(
        resty_url.parse("http://google.com"))
      assert.same(result, resty_url.parse(all_proxy_val))
    end)

    it("invalid protocol", function()
      local result = callback:get_http_proxy(
        {}, {scheme="invalid"})
      assert.is_nil(result)
    end)

  end)
end)
