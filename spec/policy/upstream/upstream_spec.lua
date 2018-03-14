local balancer = require('apicast.balancer')
local UpstreamPolicy = require('apicast.policy.upstream')

describe('Upstream policy', function()
  describe('.content', function()
    -- Set request URI and matched/non-matched upstream used in all the tests
    local test_req_uri = 'http://example.com/'
    local test_upstream_matched_host = 'localhost'
    local test_upstream_matched = string.format("http://%s/a_path:8080",
      test_upstream_matched_host)
    local test_upstream_matched_proxy_pass = 'http://upstream/a_path:8080'
    local test_upstream_not_matched = 'http://localhost/a_path:80'

    local context = {} -- Context shared between policies

    before_each(function()
      context = {}

      -- Set headers_sent to false, otherwise, the upstream is not changed
      ngx.headers_sent = false

      -- ngx functions and vars
      ngx.var = { uri = test_req_uri }
      ngx.ctx = {}
      stub(ngx.req, 'set_header')
      stub(ngx, 'exec')
    end)

    describe('when there is a rule that matches the request URI', function()
      local config_with_a_matching_rule = {
        rules = {
          { regex = '/i_dont_match', url = test_upstream_not_matched },
          { regex = '/', url = test_upstream_matched }
        }
      }

      local upstream = UpstreamPolicy.new(config_with_a_matching_rule)

      it('changes the upstream according to that rule', function()
        upstream:content(context)

        assert.equals(test_upstream_matched_proxy_pass, ngx.var.proxy_pass)
        assert.stub(ngx.req.set_header).was_called_with('Host',
          test_upstream_matched_host)
        assert.stub(ngx.exec).was_called_with('@upstream')
      end)

      it('marks in the context that the upstream has changed', function()
        upstream:content(context)
        assert.is_truthy(context.upstream_changed)
      end)
    end)

    describe('when there are several rules that match the request URI', function()
      local config_with_several_matching_rules = {
        rules = {
          { regex = '/i_dont_match', url = test_upstream_not_matched },
          { regex = '/', url = test_upstream_matched },
          { regex = '/', url = 'some_upstream_that_will_not_be_used' }
        }
      }

      local upstream = UpstreamPolicy.new(config_with_several_matching_rules)

      it('changes the upstream according to the first rule that matches', function()
        upstream:content(context)

        assert.equals(test_upstream_matched_proxy_pass, ngx.var.proxy_pass)
        assert.stub(ngx.req.set_header).was_called_with('Host',
          test_upstream_matched_host)
        assert.stub(ngx.exec).was_called_with('@upstream')
      end)

      it('marks in the context that the upstream has changed', function()
        upstream:content(context)
        assert.is_truthy(context.upstream_changed)
      end)
    end)

    describe('when there are no rules that match the request URI', function()
      local config_without_matching_rules = {
        rules = {
          { regex = '/i_dont_match', url = test_upstream_not_matched }
        }
      }

      local upstream = UpstreamPolicy.new(config_without_matching_rules)

      it('does not change the upstream', function()
        upstream:content(context)

        assert.is_nil(ngx.var.proxy_pass)
        assert.stub(ngx.req.set_header).was_not_called()
        assert.stub(ngx.exec).was_not_called()
      end)

      it('does not mark in the context that the upstream has changed', function()
        upstream:content(context)
        assert.is_falsy(context.upstream_changed)
      end)
    end)

    describe('when the port is not specified for the url', function()
      local url_without_port = 'https://127.0.0.1/a_path'
      local config_with_a_matching_rule = {
        rules = {
          { regex = '/', url = url_without_port }
        }
      }

      local upstream = UpstreamPolicy.new(config_with_a_matching_rule)

      it('sets a default port by scheme', function()
        upstream:content(context)

        assert.is_truthy(context.upstream_changed)
        assert.equals(443, ngx.ctx.upstream[1].port)
      end)

    end)
  end)

  describe('.balancer', function()
    describe('when the upstream has been changed in previous phases', function()
      it('calls the balancer', function()
        stub(balancer, 'call')
        local upstream = UpstreamPolicy.new()

        upstream:balancer({ upstream_changed = true })

        assert.stub(balancer.call).was_called()
      end)
    end)

    describe('when the upstream has not been changed in previous phases', function()
      it('does not call the balancer', function()
        stub(balancer, 'call')
        local upstream = UpstreamPolicy.new()

        for _, val in ipairs({ false, nil }) do
          upstream:balancer({ upstream_changed = val })

          assert.stub(balancer.call).was_not_called()
        end
      end)
    end)
  end)
end)
