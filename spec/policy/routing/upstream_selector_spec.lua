local UpstreamSelector = require('apicast.policy.routing.upstream_selector')
local Operation = require('apicast.conditions.operation')
local Condition = require('apicast.conditions.condition')
local TemplateString = require 'apicast.template_string'
local ngx_variable = require 'apicast.policy.ngx_variable'
local apicast_upstream = require 'apicast.upstream'

describe('UpstreamSelector', function()
  local true_condition = Condition.new(
    { Operation.new('1', 'plain', '==', '1', 'plain') },
    'and'
  )

  local false_condition = Condition.new(
    { Operation.new('1', 'plain', '!=', '1', 'plain') },
    'and'
  )

  describe('.select', function()
    describe('when there is only one rule', function()
      it('returns its upstream if the condition is true', function()
        local rules = {
          {
            url = 'http://example.com',
            condition = true_condition
          }
        }

        local upstream_selector = UpstreamSelector.new()
        local upstream = upstream_selector:select(rules, {})

        assert.equals('http', upstream.uri.scheme)
        assert.equals('example.com', upstream.uri.host)
      end)

      it('returns nil if the condition is false', function()
        local rules = {
          {
            url = 'http://example.com',
            condition = false_condition
          }
        }

        local upstream_selector = UpstreamSelector.new()
        local upstream = upstream_selector:select(rules, {})

        assert.is_nil(upstream)
      end)
    end)

    describe('when there are several rules', function()
      it('returns the upstream of the first rule that matches', function()
        local rules = {
          {
            url = 'http://example.com',
            condition = true_condition
          },
          {
            url = 'http://localhost',
            condition = true_condition
          }
        }

        local upstream_selector = UpstreamSelector.new()
        local upstream = upstream_selector:select(rules, {})

        assert.equals('http', upstream.uri.scheme)
        assert.equals('example.com', upstream.uri.host)
      end)

      it('returns nil if none of them match', function()
        local rules = {
          {
            url = 'http://example.com',
            condition = false_condition
          },
          {
            url = 'http://localhost',
            condition = false_condition
          }
        }

        local upstream_selector = UpstreamSelector.new()
        local upstream = upstream_selector:select(rules, {})

        assert.is_nil(upstream)
      end)
    end)

    describe('when there are no rules', function()
      it('returns nil', function()
        local upstream_selector = UpstreamSelector.new()
        local upstream = upstream_selector:select({}, {})

        assert.is_nil(upstream)
      end)
    end)

    describe('when rules is nil', function()
      it('returns nil', function()
        local upstream_selector = UpstreamSelector.new()
        local upstream = upstream_selector:select(nil, {})

        assert.is_nil(upstream)
      end)
    end)

    describe('when a rule that matches has a host for the Host header', function()
      describe('and it is not empty', function()
        it('sets the host for the header', function()
          local rule = {
            url = 'http://example.com',
            condition = true_condition,
            host_header = 'some_host.com'
          }

          local upstream_selector = UpstreamSelector.new()
          local upstream = upstream_selector:select({ rule }, {})

          assert.equals(rule.host_header, upstream.host)
        end)
      end)

      describe('and it is empty', function()
        it('does not set the host for the header', function()
          local rule = {
            url = 'http://example.com',
            condition = true_condition,
            host_header = ''
          }

          local upstream_selector = UpstreamSelector.new()
          local upstream = upstream_selector:select({ rule }, {})

          assert.is_nil(upstream.host)
        end)
      end)
    end)

    describe('when a rule replace the path', function()

      before_each(function()
        stub(ngx_variable, 'available_context', function(context) return context end)
        stub(ngx.req, 'set_uri', function(_) return true end)
        stub(apicast_upstream, 'append_path', function(_) return true end)
      end)

      it('is not set', function()
        local rule = {
          url = 'http://example.com',
          condition = true_condition,
        }

        local upstream_selector = UpstreamSelector.new()
        upstream_selector:select({ rule }, {})

        assert.spy(ngx.req.set_uri).was_not_called()
      end)

      it('is set with invalid liquid filter', function()
        local rule = {
          url = 'http://example.com',
          condition = true_condition,
          replace_path= TemplateString.new("", "liquid")
        }

        local upstream_selector = UpstreamSelector.new()
        local upstream = upstream_selector:select({ rule }, {})

        assert.spy(ngx.req.set_uri).was_called()
        assert.spy(ngx.req.set_uri).was.called_with("/")

        assert.spy(apicast_upstream.append_path).was_called()
        assert.spy(apicast_upstream.append_path).was.called_with(upstream, "")
      end)

      it('is correctly set', function()
        local rule = {
          url = 'http://example.com',
          condition = true_condition,
          replace_path= TemplateString.new("{{foo}}", "liquid")
        }

        local upstream_selector = UpstreamSelector.new()
        local upstream = upstream_selector:select({ rule }, {foo="bar"})

        assert.spy(ngx.req.set_uri).was_called()
        assert.spy(ngx.req.set_uri).was.called_with("/")

        assert.spy(apicast_upstream.append_path).was_called()
        assert.spy(apicast_upstream.append_path).was.called_with(upstream, "bar")
      end)
    end)

    describe('when hostname_rewrite is set ', function()
      describe('and a rule that matches has a value in host_header', function()
        it('sets the value of host_header for the host header', function()
          ctx = { service = { hostname_rewrite = "hostname_rewrite_value" } }
          local rule = {
            url = 'http://example.com',
            condition = true_condition,
            host_header = 'some_host.com'
          }

          local upstream_selector = UpstreamSelector.new()
          local upstream = upstream_selector:select({ rule }, ctx)

          assert.equals(rule.host_header, upstream.host)
        end)
      end)
      describe('and a rule that matches does not have a value in host_header', function()
        it('sets the value of hostname_rewrite for the host header', function()
          local hostname_rewrite_value = "hostname_rewrite_value"
          ctx = { service = { hostname_rewrite = hostname_rewrite_value } }
          local rule = {
            url = 'http://example.com',
            condition = true_condition
          }

          local upstream_selector = UpstreamSelector.new()
          local upstream = upstream_selector:select({ rule }, ctx)

          assert.equals(hostname_rewrite_value, upstream.host)
        end)
      end)
    end)
  end)
end)
