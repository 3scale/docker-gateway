local NamedArgsMatcher = require('apicast.policy.rewrite_url_captures.named_args_matcher')

before_each(function()
  stub(ngx.req, 'get_method', function() return 'GET' end)
end)

describe('named_args_matcher', function()
  describe('.match', function()
    describe('when there is a match', function()
      describe('and there are query args in the template and no methods', function()
        it('returns true, the new url and query args', function()
          local match_rule = "/{var_1}/blah/{var_2}/{var_3}"
          local template = "/{var_2}/something/{var_1}?my_arg={var_3}"
          local methods = {}
          local matcher = NamedArgsMatcher.new(match_rule, template, methods)
          local request_path = "/abc/blah/def/ghi"

          local matched, new_uri, args, arg_vals = matcher:match(request_path)

          assert.is_true(matched)
          assert.equals('/def/something/abc', new_uri)
          assert.same({ 'my_arg' }, args)
          assert.same({ 'ghi' }, arg_vals)
        end)
      end)

      describe('and there are query args in the template and methods', function()
        it('returns true, the new url and query args', function()
          local match_rule = "/{var_1}/blah/{var_2}/{var_3}"
          local template = "/{var_2}/something/{var_1}?my_arg={var_3}"
          local methods = {"GET", "PUT"}
          local matcher = NamedArgsMatcher.new(match_rule, template, methods)
          local request_path = "/abc/blah/def/ghi"

          local matched, new_uri, args, arg_vals = matcher:match(request_path)

          assert.is_true(matched)
          assert.equals('/def/something/abc', new_uri)
          assert.same({ 'my_arg' }, args)
          assert.same({ 'ghi' }, arg_vals)
        end)
      end)

      describe('and there are no query args in the template and no methods', function()
        it('returns true, the new url and an empty list of args', function()
          local match_rule = "/{var_1}/blah/{var_2}"
          local template = "/{var_2}/something/{var_1}"
          local methods = {}
          local matcher = NamedArgsMatcher.new(match_rule, template, methods)
          local request_path = "/abc/blah/def"

          local matched, new_uri, args, arg_vals = matcher:match(request_path)

          assert.is_true(matched)
          assert.equals('/def/something/abc', new_uri)
          assert.same({}, args)
          assert.same({}, arg_vals)
        end)
      end)

      describe('and there are methods in the template but no query args', function()
        it('returns true, the new url and an empty list of args', function()
          local match_rule = "/{var_1}/blah/{var_2}"
          local template = "/{var_2}/something/{var_1}"
          local methods = {"GET", "PUT"}
          local matcher = NamedArgsMatcher.new(match_rule, template, methods)
          local request_path = "/abc/blah/def"

          local matched, new_uri, args, arg_vals = matcher:match(request_path)

          assert.is_true(matched)
          assert.equals('/def/something/abc', new_uri)
          assert.same({}, args)
          assert.same({}, arg_vals)
        end)
      end)

      describe('and only the params part of the template has args', function()
        it('returns true, the new url and an empty list of args', function()
          local match_rule = "/v2/{var_1}"
          local template = "/?my_arg={var_1}"
          local methods = {}
          local matcher = NamedArgsMatcher.new(match_rule, template, methods)
          local request_path = "/v2/abc"

          local matched, new_uri, args, arg_vals = matcher:match(request_path)

          assert.is_true(matched)
          assert.equals('/', new_uri)
          assert.same({ 'my_arg' }, args)
          assert.same({ 'abc' }, arg_vals)
        end)
      end)

      describe('and only the params part of the template has args and methods are defined', function()
        it('returns true, the new url and an empty list of args', function()
          local match_rule = "/v2/{var_1}"
          local template = "/?my_arg={var_1}"
          local methods = {"GET", "PUT"}
          local matcher = NamedArgsMatcher.new(match_rule, template, methods)
          local request_path = "/v2/abc"
  
          local matched, new_uri, args, arg_vals = matcher:match(request_path)
  
          assert.is_true(matched)
          assert.equals('/', new_uri)
          assert.same({ 'my_arg' }, args)
          assert.same({ 'abc' }, arg_vals)
        end)
      end)
    end)

    describe('when there is not a match', function()
      describe('because no args matched', function()
        it('returns false', function()
          local match_rule = "/{var_1}/blah/{var_2}/{var_3}"
          local template = "/{var_2}/something/{var_1}?my_arg={var_3}"
          local methods = {}
          local matcher = NamedArgsMatcher.new(match_rule, template, methods)
          local request_path = "/"

          local matched = matcher:match(request_path)

          assert.is_false(matched)
        end)
      end)

      describe('because no args and no methods matched', function()
        it('returns false', function()
          local match_rule = "/{var_1}/blah/{var_2}/{var_3}"
          local template = "/{var_2}/something/{var_1}?my_arg={var_3}"
          local methods = {"PUT", "POST"}
          local matcher = NamedArgsMatcher.new(match_rule, template, methods)
          local request_path = "/"

          local matched = matcher:match(request_path)

          assert.is_false(matched)
        end)
      end)

      describe('because only some args matched', function()
        it('returns false', function()
          local match_rule = "/{var_1}/blah/{var_2}/{var_3}"
          local template = "/{var_2}/something/{var_1}?my_arg={var_3}"
          local methods = {}
          local matcher = NamedArgsMatcher.new(match_rule, template, methods)
          local request_path = "/abc/blah"

          local matched = matcher:match(request_path)

          assert.is_false(matched)
        end)
      end)

      describe('because only some args matched and no methods matched', function()
        it('returns false', function()
          local match_rule = "/{var_1}/blah/{var_2}/{var_3}"
          local template = "/{var_2}/something/{var_1}?my_arg={var_3}"
          local methods = {"PUT", "POST"}
          local matcher = NamedArgsMatcher.new(match_rule, template, methods)
          local request_path = "/abc/blah"

          local matched = matcher:match(request_path)

          assert.is_false(matched)
        end)
      end)

      describe('and there are no args in the rule', function()
        it('returns false', function()
          local match_rule = "/i_dont_match_the_request_path"
          local template = "/something"
          local matcher = NamedArgsMatcher.new(match_rule, template)
          local request_path = "/abc/def"

          local matched = matcher:match(request_path)

          assert.is_false(matched)
        end)
      end)
    end)
  end)
end)
