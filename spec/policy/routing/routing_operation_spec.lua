local RoutingOperation = require('apicast.policy.routing.routing_operation')
local ngx_variable = require 'apicast.policy.ngx_variable'

describe('RoutingOperation', function()
  describe('.evaluate', function()
    describe('when the operation involves the path', function()
      it('evaluates true conditions correctly', function()
        local path = '/some_path'

        local operation = RoutingOperation.new_op_with_path('==', path)

        local request_with_matching_path = {
          get_uri = function() return path end
        }

        local context = { request = request_with_matching_path }

        assert.is_true(operation:evaluate(context))
      end)

      it('evaluates false conditions correctly', function()
        local path = '/some_path'

        local operation = RoutingOperation.new_op_with_path('==', path)

        local request_with_different_path = {
          get_uri = function() return path .. 'some_diff' end
        }

        local context = { request = request_with_different_path }

        assert.is_false(operation:evaluate(context))
      end)
    end)

    describe('when the operation involves a header', function()
      it('evaluates true conditions correctly', function()
        local header_name = 'Test-Header'
        local header_val = 'some_value'

        local operation = RoutingOperation.new_op_with_header(
          header_name, '==', header_val
        )

        local request_with_matching_header = {
          get_header = function(_, header)
            if header == header_name then return header_val end
          end
        }

        local context = { request = request_with_matching_header }

        assert.is_true(operation:evaluate(context))
      end)

      it('evaluates false conditions correctly', function()
        local header_name = 'Test-Header'
        local header_val = 'some_value'

        local operation = RoutingOperation.new_op_with_header(
          header_name, '==', header_val
        )

        local request_with_diff_header_val = {
          get_header = function(_, header)
            if header == header_name then return header_val .. 'some_diff' end
          end
        }

        local context = { request = request_with_diff_header_val }

        assert.is_false(operation:evaluate(context))
      end)

      it('returns false when the header is not set', function()
        local operation = RoutingOperation.new_op_with_header(
          'some_header', '==', 'some_val'
        )

        local request_without_headers = {
          get_header = function() return nil end
        }

        local context = { request = request_without_headers }

        assert.is_false(operation:evaluate(context))
      end)
    end)

    describe('when the operation involves a query argument', function()
      it('evaluates true conditions correctly', function()
        local query_arg_name = 'test_query_arg'
        local query_arg_val = 'some_value'

        local operation = RoutingOperation.new_op_with_query_arg(
          query_arg_name, '==', query_arg_val
        )

        local request_with_matching_query_arg = {
          get_uri_arg = function(_, query_arg)
            if query_arg == query_arg_name then return query_arg_val end
          end
        }

        local context = { request = request_with_matching_query_arg }

        assert.is_true(operation:evaluate(context))
      end)

      it('evaluates false conditions correctly', function()
        local query_arg_name = 'test_query_arg'
        local query_arg_val = 'some_value'

        local operation = RoutingOperation.new_op_with_query_arg(
          query_arg_name, '==', query_arg_val
        )

        local request_with_diff_query_arg = {
          get_uri_arg = function(_, query_arg)
            if query_arg == query_arg_name then
              return query_arg_val .. 'some_diff'
            end
          end
        }

        local context = { request = request_with_diff_query_arg }

        assert.is_false(operation:evaluate(context))
      end)

      it('returns false when the query arg is not set', function()
        local operation = RoutingOperation.new_op_with_query_arg(
          'test_query_arg', '==', 'some_val'
        )

        local request_without_query_args = {
          get_uri_arg = function() return nil end
        }

        local context = { request = request_without_query_args }

        assert.is_false(operation:evaluate(context))
      end)
    end)

    describe('when the operation involves a jwt claim', function()
      it('evaluates true conditions correctly', function()
        local jwt_claim_name = 'test_claim'
        local jwt_claim_val = 'some_value'

        local operation = RoutingOperation.new_op_with_jwt_claim(
          jwt_claim_name, '==', jwt_claim_val
        )

        local request_with_matching_claim = {
          get_validated_jwt = function()
            return { [jwt_claim_name] = jwt_claim_val }
          end
        }

        local context = { request = request_with_matching_claim }

        assert.is_true(operation:evaluate(context))
      end)

      it('evaluates false conditions correctly', function()
        local jwt_claim_name = 'test_claim'
        local jwt_claim_val = 'some_value'

        local operation = RoutingOperation.new_op_with_jwt_claim(
          jwt_claim_name, '==', jwt_claim_val
        )

        local request_with_diff_claim_val = {
          get_validated_jwt = function()
            return { [jwt_claim_name] = jwt_claim_val .. 'some_diff' }
          end
        }

        local context = { request = request_with_diff_claim_val }

        assert.is_false(operation:evaluate(context))
      end)

      it('returns false when the jwt is not set', function()
        local operation = RoutingOperation.new_op_with_jwt_claim(
          'test_claim', '==', 'some_value'
        )

        local request_without_jwt = {
          get_validated_jwt = function()
            return nil
          end
        }

        local context = { request = request_without_jwt }

        assert.is_false(operation:evaluate(context))
      end)

      it('returns false when the jwt is set but does not have the claim', function()
        local operation = RoutingOperation.new_op_with_jwt_claim(
          'test_claim', '==', 'some_value'
        )

        local request_without_the_claim = {
          get_validated_jwt = function()
            return { some_different_claim = 'something' }
          end
        }

        local context = { request = request_without_the_claim }

        assert.is_false(operation:evaluate(context))
      end)
    end)


    describe('when the operation involves a liquid expression', function()

      before_each(function()
        stub(ngx_variable, 'available_context', function() return {foo="bar"} end)
      end)

      it('evaluates true conditions correctly', function()
        local operation = RoutingOperation.new_op_with_liquid_templating(
          "{{foo}}", "==", "bar")
        assert.is_true(operation:evaluate({}))
      end)

      it('evaluates false conditions correctly', function()
        local operation = RoutingOperation.new_op_with_liquid_templating(
          "{{foo}}", "==", "false")
        assert.is_false(operation:evaluate({}))
      end)

    end)

    it('can evaluate the right operand as liquid', function()
      -- Stub the available context to avoid depending on ngx.var.*
      stub(ngx_variable, 'available_context', function(context) return context end)

      local path = '/a_path'

      local operation = RoutingOperation.new_op_with_path(
        '==', '{{ value_in_liquid_ctx }}', 'liquid'
      )

      local request_with_matching_path = {
        get_uri = function() return path end
      }

      local context = {
        request = request_with_matching_path,
        value_in_liquid_ctx = path
      }

      assert.is_true(operation:evaluate(context))
    end)
  end)
end)
