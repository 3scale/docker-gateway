local content_caching =  require("apicast.policy.content_caching")

describe('Content Caching policy', function()
  local context = {}

  before_each(function()
    ngx.var = {}
    ngx.header = {}
    context = {}
  end)

  describe("and condition", function()
    it('matches', function()
      local config = {
        rules = {
          {
            cache = true,
            header = "",
            condition = {
              combine_op = "and",
              operations = {
                { left = "bar", op = "==", right = "bar" },
                { left = "foo", op = "==", right = "foo" }
              }
            }
          }
        }
      }

      local policy = content_caching.new(config)
      policy:access(context)
      assert.equals(ngx.var.cache_request, "")
      assert.is_nil(context[policy], nil)
    end)

    it('does not match', function()
      local config = {
        rules = {
          {
            cache = true,
            header = nil,
            condition = {
              combine_op = "and",
              operations = {
                { left = "bar", op = "==", right = "bar" },
                { left = "test", op = "==", right = "foo" }
              }
            }
          }
        }
      }

      local policy = content_caching.new(config)
      policy:access(context)
      assert.equals(ngx.var.cache_request, "true")
      assert.is_nil(context[policy], nil)
    end)
  end)

  describe('OR condition', function()

    it('matches', function()
      local config = {
        rules = {
          {
            cache = true,
            header = "",
            condition = {
              combine_op = "or",
              operations = {
                { left = "bar", op = "==", right = "bar" },
                { left = "test", op = "==", right = "foo" }
              }
            }
          }
        }
      }

      local policy = content_caching.new(config)
      policy:access(context)
      assert.equals(ngx.var.cache_request, "")
      assert.is_nil(context[policy], nil)
    end)


    it('does not match', function()
      local config = {
        rules = {
          {
            cache = true,
            header = nil,
            condition = {
              combine_op = "or",
              operations = {
                { left = "test", op = "==", right = "bar" },
                { left = "test", op = "==", right = "foo" }
              }
            }
          }
        }
      }

      local policy = content_caching.new(config)
      policy:access(context)
      assert.equals(ngx.var.cache_request, "true")
      assert.is_nil(context[policy], nil)
    end)

  end)

  describe("response header is set", function()

    local header = "RESP:HEADER"

    before_each(function()
      ngx.var.upstream_cache_status = "CACHED_RESPONSE"
    end)

    it("If hader is set", function()
      local config = {
        rules = {
          {
            cache = true,
            header = header,
            condition = {
              combine_op = "and",
              operations = {
                { left = "bar", op = "==", right = "bar" }
              }
            }
          }
        }
      }

      local policy = content_caching.new(config)

      policy:access(context)
      assert.equals(ngx.var.cache_request, "")
      assert.not_equals(context[policy], nil)
      assert.equals(context[policy].header, header)

      policy:header_filter(context)
      assert.equals(ngx.header[header], ngx.var.upstream_cache_status)
    end)

    it("Not elegible to cache, no response header is added", function()
      local config = {
        rules = {
          {
            cache = true,
            header = header,
            condition = {
              combine_op = "and",
              operations = {
                { left = "foo", op = "==", right = "bar" }
              }
            }
          }
        }
      }

      local policy = content_caching.new(config)

      policy:access(context)
      assert.equals(ngx.var.cache_request, "true")
      assert.is_nil(context[policy], nil)

      policy:header_filter(context)
      assert.is_nil(ngx.header[header])
    end)

  end)

  describe("Multiple rules", function()

    it("One rule match", function()

      local config = {
        rules = {
          {
            cache = true,
            header = "",
            condition = {
              combine_op = "and",
              operations = {
                { left = "foo", op = "==", right = "bar"}
              }
            }
          },
          {
            cache = true,
            header = "",
            condition = {
              combine_op = "and",
              operations = {
                { left = "bar", op = "==", right = "bar"}
              }
            }
          }
        }
      }

      local policy = content_caching.new(config)

      policy:access(context)
      assert.equals(ngx.var.cache_request, "")
      assert.is_nil(context[policy], nil)
    end)

    it("No rule match", function()

      local config = {
        rules = {
          {
            cache = true,
            header = "",
            condition = {
              combine_op = "and",
              operations = {
                { left = "foo", op = "==", right = "bar"}
              }
            }
          },
          {
            cache = true,
            header = "",
            condition = {
              combine_op = "and",
              operations = {
                { left = "foo", op = "==", right = "bar"}
              }
            }
          }
        }
      }

      local policy = content_caching.new(config)

      policy:access(context)
      assert.equals(ngx.var.cache_request, "true")
      assert.is_nil(context[policy], nil)
    end)

    it("First rule match stop executing", function()
      local config = {
        rules = {
          {
            cache = true,
            header = "",
            condition = {
              combine_op = "and",
              operations = {
                { left = "foo", op = "==", right = "foo"}
              }
            }
          },
          {
            cache = false,
            header = "",
            condition = {
              combine_op = "and",
              operations = {
                { left = "foo", op = "==", right = "foo"}
              }
            }
          }
        }
      }

      local policy = content_caching.new(config)

      policy:access(context)
      assert.equals(ngx.var.cache_request, "")
      assert.is_nil(context[policy], nil)
    end)

  end)

end)
