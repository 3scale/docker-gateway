local RewriteUrlCapturesPolicy = require('apicast.policy.rewrite_url_captures')
local QueryParams = require('apicast.query_params')

describe('Capture args policy', function()
  describe('.rewrite', function()
    local query_params
    local set_uri_stub
    local matching_transformation
    local non_matching_transformation

    before_each(function()
      query_params = { set = stub.new() }
      stub(QueryParams, 'new').returns(query_params)
      stub(ngx.req, 'get_method', function() return 'GET' end)
      set_uri_stub = stub(ngx.req, 'set_uri')

      ngx.var = { uri = '/abc/def' }

      matching_transformation = {
        match_rule = '/{var_1}/{var_2}',
        template = '/{var_2}?my_arg={var_1}',
        methods = {'GET'}
      }

      non_matching_transformation = {
        match_rule = '/i_dont_match/{var_1}/{var_2}',
        template = '/{var_2}?my_arg={var_1}',
        methods = {'GET'}
      }

      matching_transformation_no_method = {
        match_rule = '/{var1}/{var2}',
        template = '/{var2}?my_arg={var1}',
        methods = {}
      }
    end)

    describe('when there is a match', function()
      it('modifies the path and the params', function()
        local transformations = {
          non_matching_transformation,
          matching_transformation
        }
        local rewrite_url_captures = RewriteUrlCapturesPolicy.new(
          { transformations = transformations }
        )

        rewrite_url_captures:rewrite()

        assert.stub(set_uri_stub).was_called_with('/def')
        assert.stub(query_params.set).was_called_with(
          query_params, 'my_arg', 'abc')
      end)
    end)

    describe('when there is a match but method does not match', function()
      it('does not modifiy the path nor the params', function()
        local transformations = {
          non_matching_transformation,
          matching_transformation
        }
        ngx.req.get_method:revert()
        stub(ngx.req, 'get_method', function() return 'PUT' end)
        local rewrite_url_captures = RewriteUrlCapturesPolicy.new(
          { transformations = transformations }
        )

        rewrite_url_captures:rewrite()

        assert.stub(set_uri_stub).was_not_called()
        assert.stub(query_params.set).was_not_called()
      end)
    end)

    describe('when there is a match but no method is defined', function()
      it('modifies the path and the params', function()
        local transformations = {
          non_matching_transformation,
          matching_transformation,
          matching_transformation_no_method
        }
        local rewrite_url_captures = RewriteUrlCapturesPolicy.new(
          { transformations = transformations }
        )

        rewrite_url_captures:rewrite()

        assert.stub(set_uri_stub).was_called_with('/def')
        assert.stub(query_params.set).was_called_with(
          query_params, 'my_arg', 'abc')
      end)
    end)

    describe('when there are several matches', function()
      it('modifies path and params according to the 1st match only', function()
        local another_matching_transformation = {
          match_rule = '/{var_1}/{var_2}',

          -- Swap var_1 and var_2 in the original one.
          template = '/{var_1}?my_arg={var_2}',
          methods = {'POST'}
        }

        local transformations = {
          non_matching_transformation,
          matching_transformation,
          another_matching_transformation -- Will be ignored
        }

        local rewrite_url_captures = RewriteUrlCapturesPolicy.new(
          { transformations = transformations }
        )

        rewrite_url_captures:rewrite()

        assert.stub(set_uri_stub).was_called_with('/def')
        assert.stub(query_params.set).was_called_with(
          query_params, 'my_arg', 'abc')
      end)
    end)

    describe('when there is not a match', function()
      it('does not modify the path nor the params', function()
        local transformations = { non_matching_transformation }
        local rewrite_url_captures = RewriteUrlCapturesPolicy.new(
          { transformations = transformations }
        )

        rewrite_url_captures:rewrite()

        assert.stub(set_uri_stub).was_not_called()
        assert.stub(query_params.set).was_not_called()
      end)
    end)
  end)
end)
