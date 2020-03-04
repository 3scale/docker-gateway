local Usage = require('apicast.usage')

describe('SOAP policy', function()
  describe('.rewrite', function()
    local context -- Context shared between policies

    local base_url = "http://www.example.com:80"
    local base_path = "/path/to/myfile.html?key1=value1&key2=value2#SomewhereInTheDocument"
    local full_url = base_url .. base_path
    -- Define a config with 3 rules. Their patterns have values that allow us
    -- to easily associate them with a SOAP action receive via SOAPAction
    -- header or via Content-Type. The third one is used to tests matching of
    -- full URLs.
    local policy_config = {
      mapping_rules = {
        {
          pattern = '/soap_action$',
          metric_system_name = 'hits',
          delta = 10
        },
        {
          pattern = '/soap_action_ctype$',
          metric_system_name = 'hits',
          delta = 20
        },
        {
          pattern = base_path,
          metric_system_name = 'hits',
          delta = 30
        },
      }
    }

    local soap_policy = require('apicast.policy.soap').new(policy_config)

    before_each(function()
      -- Initialize a shared context with a usage of hits = 1.
      context = { usage = Usage.new() }
      context.usage:add('hits', 1)
    end)

    describe('when the SOAP action is in the SOAPAction header', function()
      it('calculates the usage and merges it with the one in the context', function()
        ngx.req.get_headers = function()
          return { SOAPAction = '/soap_action' }
        end

        soap_policy:rewrite(context)

        assert.equals(11, context.usage.deltas['hits'])
      end)
    end)

    describe('when the SOAP action is in the Content-Type header', function()
      describe('and it is the only param', function()
        it('calculates the usage and merges it with the one in the context', function()
          local header_val = "application/soap+xml;action=/soap_action_ctype"

          ngx.req.get_headers = function()
            return { ["Content-Type"] = header_val }
          end

          soap_policy:rewrite(context)

          assert.equals(21, context.usage.deltas['hits'])
        end)
      end)

      describe('and there are other params', function()
        it('calculates the usage and merges it with the one in the context', function()
          local header_val = "application/soap+xml;a_param=x;" ..
              "action=/soap_action_ctype;another_param=y"

          ngx.req.get_headers = function()
            return { ["Content-Type"] = header_val }
          end

          soap_policy:rewrite(context)

          assert.equals(21, context.usage.deltas['hits'])
        end)
      end)

      describe('and the params contain some upper-case chars or spaces', function()
        it('calculates the usage and merges it with the one in the context', function()
          local header_vals = {
            -- Upper-case chars in type/subtype
            "Application/SOAP+xml;action=/soap_action_ctype",
            -- Upper-case chars in 'Action'
            "application/soap+xml;Action=/soap_action_ctype",
            -- "" in action value
            'application/soap+xml;action="/soap_action_ctype"',
            -- Spaces
            "application/soap+xml; action=/soap_action_ctype; a_param=x"
          }

          for _, header_val in ipairs(header_vals) do
            ngx.req.get_headers = function()
              return { ["Content-Type"] = header_val }
            end

            context = { usage = Usage.new() }
            context.usage:add('hits', 1)
            soap_policy:rewrite(context)

            assert.equals(21, context.usage.deltas['hits'])
          end
        end)
      end)

      describe('and the action is a full URL', function()
        it('calculates the usage and merges it with the one in the context', function()
          ngx.req.get_headers = function()
            return { ["Content-Type"] = 'application/soap+xml;action=' .. full_url }
          end

          soap_policy:rewrite(context)

          assert.equals(31, context.usage.deltas['hits'])
        end)
      end)
    end)

    describe('when the SOAP action is in the SOAPAction and the Content-Type headers', function()
      it('calculates the usage and merges it with the one in the context', function()
        ngx.req.get_headers = function()
          return {
            SOAPAction = '/soap_action',
            ["Content-Type"] = "application/soap+xml;action=/soap_action_ctype"
          }
        end

        soap_policy:rewrite(context)

        assert.equals(21, context.usage.deltas['hits'])
      end)
    end)

    describe('when the SOAP action is not specified', function()
      it('it does not modify the usage received in the context', function()
        ngx.req.get_headers = function() return {} end

        soap_policy:rewrite(context)

        assert.equals(1, context.usage.deltas['hits'])
      end)
    end)
  end)
end)
