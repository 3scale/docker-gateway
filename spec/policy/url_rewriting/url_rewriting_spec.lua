local URLRewriting = require('apicast.policy.url_rewriting')

describe('URL rewriting policy', function()
  describe('.rewrite', function()
    local original_uri
    local context

    before_each(function()
      context = {}
      original_uri = '/some_path/to_be_replaced/123/to_be_replaced'
      ngx.var = { uri = original_uri }

      stub(ngx.req, 'set_uri', function(new_uri)
        ngx.var.uri = new_uri
      end)
    end)

    it('can rewrite URLs using sub', function()
      local config_with_sub = {
        commands = {
          { op = 'sub', regex = 'to_be_replaced', replace = 'new' }
        }
      }
      local url_rewriting = URLRewriting.new(config_with_sub)

      url_rewriting:rewrite(context)

      assert.stub(ngx.req.set_uri).was_called_with('/some_path/new/123/to_be_replaced')
    end)


    it('can rewrite URLs using gsub', function()
      local config_with_gsub = {
        commands = {
          { op = 'gsub', regex = 'to_be_replaced', replace = 'new' }
        }
      }
      local url_rewriting = URLRewriting.new(config_with_gsub)

      url_rewriting:rewrite(context)

      assert.stub(ngx.req.set_uri).was_called_with('/some_path/new/123/new')
    end)

    it('applies the commands in order', function()
      local config_with_several_ops = {
        commands = {
          { op = 'gsub', regex = 'to_be_replaced', replace = 'abc' },
          { op = 'gsub', regex = 'abc', replace = 'def' },
          { op = 'gsub', regex = 'def', replace = 'ghi' }
        }
      }
      local url_rewriting = URLRewriting.new(config_with_several_ops)

      url_rewriting:rewrite(context)

      assert.equals('/some_path/ghi/123/ghi', ngx.var.uri)
    end)

    it('when there is a break, stops at the first match', function()
      local config_with_break = {
        commands = {
          { op = 'gsub', regex = 'to_be_replaced', replace = 'abc', ['break'] = true },
          { op = 'gsub', regex = 'abc', replace = 'def' } -- Not applied
        }
      }
      local url_rewriting = URLRewriting.new(config_with_break)

      url_rewriting:rewrite(context)

      assert.equals('/some_path/abc/123/abc', ngx.var.uri)
    end)

    it('accepts options for the regexes, same as ngx.req.{sub, gsub}', function()
      local config_with_regex_opts = {
        commands = {
          { op = 'gsub', regex = 'TO_BE_REPLACED', replace = 'new', options = 'i' }
        }
      }
      local url_rewriting = URLRewriting.new(config_with_regex_opts)

      url_rewriting:rewrite(context)

      assert.stub(ngx.req.set_uri).was_called_with('/some_path/new/123/new')
    end)

    it('adds the original URI to the context', function()
      local url_rewriting = URLRewriting.new({ commands = {} })

      url_rewriting:rewrite(context)

      assert.equals(original_uri, context.original_uri)
    end)
  end)
end)
