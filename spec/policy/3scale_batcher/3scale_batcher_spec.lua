local ThreescaleBatcher = require('apicast.policy.3scale_batcher')
local AuthsCache = require('apicast.policy.3scale_batcher.auths_cache')
local Transaction = require('apicast.policy.3scale_batcher.transaction')
local Usage = require('apicast.usage')
local configuration = require('apicast.configuration')
local lrucache = require('resty.lrucache')
local TimerTask = require('resty.concurrent.timer_task')
local Metrics = require('apicast.policy.3scale_batcher.metrics')

describe('3scale batcher policy', function()
  before_each(function()
    TimerTask.active_tasks = {}
  end)

  describe('.new', function()
    it('allows to configure the batching period', function()
      local test_batching_period = 3
      local config = { batch_report_seconds = test_batching_period }
      local batcher_policy = ThreescaleBatcher.new(config)

      assert.equals(test_batching_period, batcher_policy.batch_reports_seconds)
    end)

    it('assigns a default of 10s for the batching period', function()
      local batcher_policy = ThreescaleBatcher.new({})

      assert.equals(10, batcher_policy.batch_reports_seconds)
    end)
  end)

  describe('.rewrite', function()
    it('sets flag to avoid calling backend in the APIcast policy', function()
      local context = {}
      local batcher_policy = ThreescaleBatcher.new({})

      batcher_policy:rewrite(context)

      assert.is_true(context.skip_apicast_access)
    end)
  end)

  describe('.access', function()
    local service = configuration.parse_service({ id = 42 })
    local service_id = service.id
    local credentials = { user_key = 'uk' }
    local usage = Usage.new()
    usage:add('m1', 1)
    local transaction = Transaction.new(service_id, credentials, usage)

    local context
    local batcher_policy

    before_each(function()
      ngx.var = {}
      ngx.header = {}
      stub(ngx, 'print')

      batcher_policy = ThreescaleBatcher.new({})
      batcher_policy.auths_cache = AuthsCache.new(lrucache.new(10), 10)
      stub(batcher_policy.reports_batcher, 'add')

      -- if a report job executes, by default, stub the batcher so it returns
      -- no pending reports.
      stub(batcher_policy.reports_batcher, 'get_all').returns({})

      -- By default return a hit in the caches to simplify tests
      local backend_client = require('apicast.backend_client')
      stub(backend_client, 'authorize').returns({ status = 200 })
      stub(batcher_policy,'backend_downtime_cache')
      stub(batcher_policy.backend_downtime_cache, 'get').returns(200)

      stub(Metrics, 'update_cache_counters')

      context = {
        service = service,
        usage = usage,
        credentials = credentials,
        -- cache_handler does nothing because we just need to check if it's called
        cache_handler = function() end,
        publish_backend_auth = function() end
      }

      stub(context, 'cache_handler')
    end)

    describe('when mapping rule does not match', function()
      it('returns 404 back', function()
        context.usage = Usage.new()
        batcher_policy:access(context)
        assert.equals(ngx.status, 404)
      end)
    end)

    describe('when the request is cached', function()
      it('updates the auths cache counter sending a hit', function()
        batcher_policy.auths_cache:set(transaction, 200)

        batcher_policy:access(context)

        assert.stub(Metrics.update_cache_counters).was_called_with(true)
      end)

      describe('and it is authorized', function()
        it('adds the report to the batcher', function()
          batcher_policy.auths_cache:set(transaction, 200)

          batcher_policy:access(context)

          assert.stub(batcher_policy.reports_batcher.add).was_called_with(
            batcher_policy.reports_batcher, transaction)
        end)
      end)

      describe('and it is not authorized', function()
        it('does not add the report to the batcher', function()
          batcher_policy.auths_cache:set(transaction, 409, 'limits_exceeded')

          batcher_policy:access(context)

          assert.stub(batcher_policy.reports_batcher.add).was_not_called()
        end)

        it('returns an error', function()
          batcher_policy.auths_cache:set(transaction, 409, 'limits_exceeded')

          batcher_policy:access(context)

          assert.is_true(ngx.status >= 400 and ngx.status < 500)
        end)
      end)
    end)

    describe('when the request is not cached', function()
      it('updates the auths cache counter sending a miss', function()
        batcher_policy:access(context)

        assert.stub(Metrics.update_cache_counters).was_called_with(false)
      end)

      describe('and backend is available', function()
        before_each(function()
          local backend_client = require('apicast.backend_client')
          backend_client.authorize:revert()
          stub(backend_client, 'authorize').returns({ status = 200 })
        end)

        it('updates the backend downtime cache using the handler in the context', function()
          batcher_policy:access(context)

          assert.stub(context.cache_handler).was_called()
        end)
      end)

      describe('and backend is not available', function()
        before_each(function()
          local backend_client = require('apicast.backend_client')
          backend_client.authorize:revert()
          stub(backend_client, 'authorize').returns({ status = 500 })
        end)

        describe('and the authorization is in the downtime cache', function()
          describe('and it is OK', function()
            before_each(function()
              batcher_policy.backend_downtime_cache.get:revert()
              stub(batcher_policy.backend_downtime_cache, 'get').returns(200)
            end)

            it('adds the report to the batcher', function()
              batcher_policy:access(context)

              assert.stub(batcher_policy.reports_batcher.add).was_called_with(
                batcher_policy.reports_batcher, transaction)
            end)
          end)

          describe('and it is denied', function()
            before_each(function()
              batcher_policy.backend_downtime_cache.get:revert()
              stub(batcher_policy.backend_downtime_cache, 'get').returns(409)
            end)

            it('does not add the report to the batcher', function()
              batcher_policy:access(context)

              assert.stub(batcher_policy.reports_batcher.add).was_not_called()
            end)

            it('returns an error', function()
              batcher_policy:access(context)

              assert.is_true(ngx.status >= 400 and ngx.status < 500)
            end)
          end)
        end)

        describe('and the authorization is not in the downtime cache', function()
          before_each(function()
            batcher_policy.backend_downtime_cache.get:revert()
            stub(batcher_policy.backend_downtime_cache, 'get').returns(nil)
          end)

          it('returns an error', function()
            batcher_policy:access(context)

            assert.is_true(ngx.status >= 400 and ngx.status < 500)
          end)
        end)
      end)
    end)
  end)
end)
