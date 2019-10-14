local RoutingPolicy = require('apicast.policy.routing')
local UpstreamSelector = require('apicast.policy.routing.upstream_selector')
local Request = require('apicast.policy.routing.request')
local Upstream = require('apicast.upstream')

describe('Routing policy', function()
  describe('.content', function()
    describe('when there is an upstream that matches', function()
      local upstream_that_matches = Upstream.new('http://localhost')
      stub(upstream_that_matches, 'call')

      local upstream_selector = UpstreamSelector.new()
      stub(upstream_selector, 'select').returns(upstream_that_matches)

      local request = Request.new()
      local context = { request = request }

      it('calls call() on the upstream passing the context as param', function()
        local routing = RoutingPolicy.new()

        routing.upstream_selector = upstream_selector
        routing:access(context)
        routing:content(context)

        assert.stub(upstream_selector.select).was_called_with(
          upstream_selector, routing.rules, {request=request}
        )

        assert.stub(upstream_that_matches.call).was_called_with(
          upstream_that_matches, context
        )
      end)
    end)

    describe('when there is not an upstream that matches', function()
      local upstream_selector = UpstreamSelector.new()
      stub(upstream_selector, 'select').returns(nil)

      local request = Request.new()
      local context = { request = request }

      it('returns nil and the msg "no upstream"', function()
        local routing = RoutingPolicy.new()
        routing.upstream_selector = upstream_selector
        routing:access(context)
        local res, err = routing:content(context)

        assert.is_nil(res)
        assert.equals('no upstream', err)
      end)
    end)
  end)
end)
