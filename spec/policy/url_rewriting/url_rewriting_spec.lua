local URLRewriting = require('apicast.policy.url_rewriting')
local ngx_variable = require('apicast.policy.ngx_variable')

-- Mock QueryParams module. In these tests we are only interested in checking
-- that a QueryParams instance is called with the appropriate params. We do
-- not want to check its internals.
local QueryParams = require('apicast.query_params')
local noop = function() end

describe('URL rewriting policy', function()

  local mocked_query_params = { push = noop, set = noop, add = noop, delete = noop }
  local spy_mocked_query_params_push
  local spy_mocked_query_params_set
  local spy_mocked_query_params_add
  local spy_mocked_query_params_delete

  before_each(function ()
    stub(QueryParams, 'new', function() return mocked_query_params end)

    -- avoid stubbing all the ngx.var.* and ngx.req.* in the available context
    stub(ngx_variable, 'available_context', function(context) return context end)
  end)

  describe('.rewrite', function()
    before_each(function()
      ngx.var = { uri = '/some_path/to_be_replaced/123/to_be_replaced' }

      stub(ngx.req, 'set_uri', function(new_uri)
        ngx.var.uri = new_uri
      end)

      stub(ngx.req, 'get_method', function() return 'GET' end)
      stub(ngx.req, 'get_uri_args', function() return {} end)
      stub(ngx.req, 'set_uri_args')

      spy_mocked_query_params_push = spy.on(mocked_query_params, 'push')
      spy_mocked_query_params_set = spy.on(mocked_query_params, 'set')
      spy_mocked_query_params_add = spy.on(mocked_query_params, 'add')
      spy_mocked_query_params_delete = spy.on(mocked_query_params, 'delete')
    end)

    it('can rewrite URLs using sub', function()
      local config_with_sub = {
        commands = {
          { op = 'sub', regex = 'to_be_replaced', replace = 'new' }
        }
      }
      local url_rewriting = URLRewriting.new(config_with_sub)

      url_rewriting:rewrite()

      assert.stub(ngx.req.set_uri).was_called_with('/some_path/new/123/to_be_replaced')
    end)


    it('can rewrite URLs using gsub', function()
      local config_with_gsub = {
        commands = {
          { op = 'gsub', regex = 'to_be_replaced', replace = 'new' }
        }
      }
      local url_rewriting = URLRewriting.new(config_with_gsub)

      url_rewriting:rewrite()

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

      url_rewriting:rewrite()

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

      url_rewriting:rewrite()

      assert.equals('/some_path/abc/123/abc', ngx.var.uri)
    end)

    it('accepts options for the regexes, same as ngx.req.{sub, gsub}', function()
      local config_with_regex_opts = {
        commands = {
          { op = 'gsub', regex = 'TO_BE_REPLACED', replace = 'new', options = 'i' }
        }
      }
      local url_rewriting = URLRewriting.new(config_with_regex_opts)

      url_rewriting:rewrite()

      assert.stub(ngx.req.set_uri).was_called_with('/some_path/new/123/new')
    end)

    it('can apply the "push" operation to args in the query', function()
      local config_to_push_args = {
        query_args_commands = {
          { op = 'push', arg = 'an_arg', value = '1' }
        }
      }
      local url_rewriting = URLRewriting.new(config_to_push_args)

      url_rewriting:rewrite()

      assert.spy(spy_mocked_query_params_push).was_called_with(
        mocked_query_params, 'an_arg', '1')
    end)

    it('can apply the "set" operation to args in the query', function()
      local config_to_set_args = {
        query_args_commands = {
          { op = 'set', arg = 'an_arg', value = '1' }
        }
      }
      local url_rewriting = URLRewriting.new(config_to_set_args)

      url_rewriting:rewrite()

      assert.spy(spy_mocked_query_params_set).was_called_with(
        mocked_query_params, 'an_arg', '1')
    end)

    it('can apply the "add" operation to args in the query', function()
      local config_to_add_args = {
        query_args_commands = {
          { op = 'add', arg = 'an_arg', value = '1' }
        }
      }
      local url_rewriting = URLRewriting.new(config_to_add_args)

      url_rewriting:rewrite()

      assert.spy(spy_mocked_query_params_add).was_called_with(
        mocked_query_params, 'an_arg', '1')
    end)

    it('can apply the "delete" operation to args in the query', function()
      local config_to_delete_args = {
        query_args_commands = {
          { op = 'delete', arg = 'an_arg' }
        }
      }
      local url_rewriting = URLRewriting.new(config_to_delete_args)

      url_rewriting:rewrite()

      assert.spy(spy_mocked_query_params_delete).was_called_with(
        mocked_query_params, 'an_arg', nil)
    end)

    it('supports liquid templates when pushing query args', function()
      local context = { var_in_context = '123' }

      local config_with_liquid = {
        query_args_commands = {
          {
            op = 'push',
            arg = 'an_arg',
            value = '{{ var_in_context }}',
            value_type = 'liquid'
          }
        }
      }

      local url_rewriting = URLRewriting.new(config_with_liquid)

      url_rewriting:rewrite(context)

      assert.spy(spy_mocked_query_params_push).was_called_with(
        mocked_query_params, 'an_arg', context.var_in_context)
    end)

    it('supports liquid templates when setting query args', function()
      local context = { var_in_context = '123' }

      local config_with_liquid = {
        query_args_commands = {
          {
            op = 'set',
            arg = 'an_arg',
            value = '{{ var_in_context }}',
            value_type = 'liquid'
          }
        }
      }

      local url_rewriting = URLRewriting.new(config_with_liquid)

      url_rewriting:rewrite(context)

      assert.spy(spy_mocked_query_params_set).was_called_with(
        mocked_query_params, 'an_arg', context.var_in_context)
    end)

    it('supports liquid templates when adding query args', function()
      local context = { var_in_context = '123' }

      local config_with_liquid = {
        query_args_commands = {
          {
            op = 'add',
            arg = 'an_arg',
            value = '{{ var_in_context }}',
            value_type = 'liquid'
          }
        }
      }

      local url_rewriting = URLRewriting.new(config_with_liquid)

      url_rewriting:rewrite(context)

      assert.spy(spy_mocked_query_params_add).was_called_with(
        mocked_query_params, 'an_arg', context.var_in_context)
    end)

    it('only rewrite URL with GET method', function()
      local config_with_sub = {
        commands = {
          {op = 'sub', regex = 'to_be_replaced', replace = 'new', methods = {'GET'} }
        }
      }
      local url_rewriting = URLRewriting.new(config_with_sub)

      url_rewriting:rewrite()

      assert.stub(ngx.req.set_uri).was_called_with('/some_path/new/123/to_be_replaced')
    end)

    it('should rewrite URL with method in array', function()
      local config_with_sub = {
        commands = {
          {op = 'sub', regex = 'to_be_replaced', replace = 'new', methods = {'POST', 'GET'} }
        }
      }
      local url_rewriting = URLRewriting.new(config_with_sub)

      url_rewriting:rewrite()

      assert.stub(ngx.req.set_uri).was_called_with('/some_path/new/123/to_be_replaced')
    end)

    it('should rewrite URL with an empty methods array', function()
      local config_with_sub = {
        commands = {
          {op = 'sub', regex = 'to_be_replaced', replace = 'new', methods = {} }
        }
      }
      local url_rewriting = URLRewriting.new(config_with_sub)

      url_rewriting:rewrite()

      assert.stub(ngx.req.set_uri).was_called_with('/some_path/new/123/to_be_replaced')
    end)

    it('should not execute rewrite for different method as configured', function()
      local config_with_sub = {
        commands = {
          {op = 'sub', regex = 'to_be_replaced', replace = 'new', methods = {'POST'} }
        }
      }
      
      local url_rewriting = URLRewriting.new(config_with_sub)
      
      url_rewriting:rewrite()

      assert.stub(ngx.req.set_uri).was_not_called()
    end)

    it('should not execute rewrite for different method as configured', function()
      local config_with_sub = {
        commands = {
          {op = 'sub', regex = 'to_be_replaced', replace = 'new', methods = {'PATCH', 'PUT', 'DELETE'} }
        }
      }
      
      local url_rewriting = URLRewriting.new(config_with_sub)
      
      url_rewriting:rewrite()

      assert.stub(ngx.req.set_uri).was_not_called()
    end)

    it('can apply the "push" operation to args in the query when the method is provided in the config', function()
      local config_to_push_args = {
        query_args_commands = {
          { op = 'push', arg = 'an_arg', value = '1', methods = {'GET'} }
        }
      }
      local url_rewriting = URLRewriting.new(config_to_push_args)

      url_rewriting:rewrite()

      assert.spy(spy_mocked_query_params_push).was_called_with(
        mocked_query_params, 'an_arg', '1')
    end)

    it('can apply the "push" operation to args in the query when the method is provided in the config list', function()
      local config_to_push_args = {
        query_args_commands = {
          { op = 'push', arg = 'an_arg', value = '1', methods = {'POST', 'GET'} }
        }
      }
      local url_rewriting = URLRewriting.new(config_to_push_args)

      url_rewriting:rewrite()

      assert.spy(spy_mocked_query_params_push).was_called_with(
        mocked_query_params, 'an_arg', '1')
    end)

    it('will not apply the "push" operation to args in the query when the method is not provided in the config', function()
      local config_to_push_args = {
        query_args_commands = {
          { op = 'push', arg = 'an_arg', value = '1', methods = {'POST'} }
        }
      }
      local url_rewriting = URLRewriting.new(config_to_push_args)

      url_rewriting:rewrite()

      assert.spy(spy_mocked_query_params_push).was_not_called()
    end)

    it('will not apply the "push" operation to args in the query when the method is not provided in the config list', function()
      local config_to_push_args = {
        query_args_commands = {
          { op = 'push', arg = 'an_arg', value = '1', methods = {'POST', 'DELETE', 'PATCH'} }
        }
      }
      local url_rewriting = URLRewriting.new(config_to_push_args)

      url_rewriting:rewrite()

      assert.spy(spy_mocked_query_params_push).was_not_called()
    end)

    it('can apply the "push" operation to args in the query when the method list in the config is empty', function()
      local config_to_push_args = {
        query_args_commands = {
          { op = 'push', arg = 'an_arg', value = '1', methods = {} }
        }
      }
      local url_rewriting = URLRewriting.new(config_to_push_args)

      url_rewriting:rewrite()

      assert.spy(spy_mocked_query_params_push).was_called_with(
        mocked_query_params, 'an_arg', '1')
    end)

  end)
end)
