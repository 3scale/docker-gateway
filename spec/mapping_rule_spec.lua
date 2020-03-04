local MappingRule = require('apicast.mapping_rule')

describe('mapping_rule', function()
  describe('.from_proxy_rule', function()
    it('sets "last"', function()
      local mapping_rule = MappingRule.from_proxy_rule({
        last = true,
        http_method = 'GET',
        pattern = '/abc',
        querystring_parameters = { a_param = '1' },
        metric_system_name = 'hits',
        delta = 1
      })

      assert.is_true(mapping_rule.last)
    end)

    it('sets "last" to false by default', function()
      local mapping_rule = MappingRule.from_proxy_rule({
        http_method = 'GET',
        pattern = '/abc',
        querystring_parameters = { a_param = '1' },
        metric_system_name = 'hits',
        delta = 1
      })

      assert.is_false(mapping_rule.last)
    end)
  end)

  describe('.matches', function()
    it('returns true when method, URI, and args match', function()
      local mapping_rule = MappingRule.from_proxy_rule({
        http_method = 'GET',
        pattern = '/abc',
        querystring_parameters = { a_param = '1' },
        metric_system_name = 'hits',
        delta = 1
      })

      local match = mapping_rule:matches('GET', '/abc', { a_param = '1' })
      assert.is_true(match)
    end)

    it('returns true when method and URI match, and no args are required', function()
      local mapping_rule = MappingRule.from_proxy_rule({
        http_method = 'GET',
        pattern = '/abc',
        querystring_parameters = { },
        metric_system_name = 'hits',
        delta = 1
      })

      local match = mapping_rule:matches('GET', '/abc', { a_param = '1' })
      assert.is_true(match)
    end)

    it('returns false when the method does not match', function()
      local mapping_rule = MappingRule.from_proxy_rule({
        http_method = 'GET',
        pattern = '/abc',
        querystring_parameters = { a_param = '1' },
        metric_system_name = 'hits',
        delta = 1
      })

      local match = mapping_rule:matches('POST', '/abc', { a_param = '1' })
      assert.is_false(match)
    end)

    it('returns false when the URI does not match', function()
      local mapping_rule = MappingRule.from_proxy_rule({
        http_method = 'GET',
        pattern = '/abc',
        querystring_parameters = { a_param = '1' },
        metric_system_name = 'hits',
        delta = 1
      })

      local match = mapping_rule:matches('GET', '/aaa', { a_param = '1' })
      assert.is_false(match)
    end)

    it('returns false when the args do not match', function()
      local mapping_rule = MappingRule.from_proxy_rule({
        http_method = 'GET',
        pattern = '/abc',
        querystring_parameters = { a_param = '1' },
        metric_system_name = 'hits',
        delta = 1
      })

      local match = mapping_rule:matches('GET', '/abc', { a_param = '2' })
      assert.is_false(match)
    end)

    it('returns false when method, URI, and args do not match', function()
      local mapping_rule = MappingRule.from_proxy_rule({
        http_method = 'GET',
        pattern = '/abc',
        querystring_parameters = { a_param = '1' },
        metric_system_name = 'hits',
        delta = 1
      })

      local match = mapping_rule:matches('POST', '/def', { x = 'y' })
      assert.is_false(match)
    end)

    it('returns true when wildcard value has special characters: @ : % etc.', function()
      local mapping_rule = MappingRule.from_proxy_rule({
        http_method = 'GET',
        pattern = '/foo/{wildcard}/bar',
        querystring_parameters = { },
        metric_system_name = 'hits',
        delta = 1
      })

      assert.is_true(mapping_rule:matches('GET', '/foo/a@b/bar'))
      assert.is_true(mapping_rule:matches('GET', '/foo/a:b/bar'))
      assert.is_true(mapping_rule:matches('GET', "/foo/a%b/bar"))
    end)

    it('double slashes are transformed correctly to a simple one', function()
        local test_cases = {
            ["/foo//bar"] = "/foo/bar",
            ["/foo///bar"] = "/foo/bar",
            ["/foo/ /bar"] = "/foo/ /bar",
            ["/foo/bar///"] = "/foo/bar/",
            ["///foo///bar///"] = "/foo/bar/",
        }

        for key, value in pairs(test_cases) do
          local mapping_rule = MappingRule.from_proxy_rule({
            http_method = 'GET',
            pattern = key,
            querystring_parameters = { },
            metric_system_name = 'hits',
            delta = 1
          })

          assert.is_true(mapping_rule:matches('GET', value), "Invalid key:" .. key)
        end

    end)
  end)

  describe('.any_method', function()

    it("Allow connections when any method is defined", function()

      local mapping_rule = MappingRule.from_proxy_rule({
        http_method = MappingRule.any_method,
        pattern = '/foo/',
        querystring_parameters = { },
        metric_system_name = 'hits',
        delta = 1
      })

      assert.is_true(mapping_rule:matches('GET', '/foo/'))
      assert.is_true(mapping_rule:matches('POST', '/foo/'))
      assert.is_true(mapping_rule:matches('PUT', "/foo/"))
      assert.is_true(mapping_rule:matches('DELETE', "/foo/"))
      assert.is_true(mapping_rule:matches('PATCH', "/foo/"))
    end)
  end)

end)
