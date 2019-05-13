describe('upstream metrics', function()
  describe('report', function()
    local upstream_metrics
    local test_counter = { inc = function() end }
    local test_histogram = { observe = function() end }

    before_each(function()
      -- Make Prometheus return stubbed counters and histograms
      stub(test_counter, 'inc')
      stub(test_histogram, 'observe')

      local Prometheus = require('apicast.prometheus')
      getmetatable(Prometheus).__call = function(_, type)
        if type == 'counter' then
          return test_counter
        elseif type == 'histogram' then
          return test_histogram
        end
      end

      package.loaded['apicast.metrics.upstream'] = nil
      upstream_metrics = require('apicast.metrics.upstream')
    end)

    after_each(function()
      package.loaded['apicast.prometheus'] = nil
      require('apicast.prometheus')

      package.loaded['apicast.metrics.upstream'] = nil
      require('apicast.metrics.upstream')
    end)

    it('increases the counter of status codes', function()
      upstream_metrics.report(200, 0.1)
      assert.stub(test_counter.inc).was_called_with(test_counter, 1, { 200, "", "" })
    end)

    it('adds the latency to the histogram', function()
      upstream_metrics.report(200, 0.1)
      assert.stub(test_histogram.observe).was_called_with(test_histogram, 0.1, {"", ""})
    end)

    describe('when the status is nil or empty', function()
      it('does not increase the counter of status codes', function()
        upstream_metrics.report(nil, 0.1)
        upstream_metrics.report('', 0.1)
        assert.stub(test_counter.inc).was_not_called()
      end)
    end)

    describe('when the latency is nil or empty', function()
      it('does not add the latency to the histogram', function()
        upstream_metrics.report(200, nil)
        upstream_metrics.report(200, '')
        assert.stub(test_histogram.observe).was_not_called()
      end)
    end)


    describe('With service id', function()
      local service = {id = "123", system_name="foo"}
      it("increases empty service on nil", function()
        upstream_metrics.report(200, 0.1, nil)
        assert.stub(test_histogram.observe).was_called_with(test_histogram, 0.1, {"", ""})
        assert.stub(test_counter.inc).was_called_with(test_counter, 1, { 200, "", "" })
      end)

      it("increase a valid service", function()
        upstream_metrics.report(200, 0.1, service)
        assert.stub(test_histogram.observe).was_called_with(test_histogram, 0.1, { service.id, service.system_name })
        assert.stub(test_counter.inc).was_called_with(test_counter, 1, { 200, service.id, service.system_name })
      end)
    end)
  end)
end)
