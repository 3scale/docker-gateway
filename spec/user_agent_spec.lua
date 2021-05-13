local user_agent = require 'apicast.user_agent'
local ffi = require("ffi")
local env = require 'resty.env'

describe('User Agent', function()
  before_each(function() user_agent.reset() end)

  describe('.deployment', function()
    it('reads from environment', function()
      env.set('THREESCALE_DEPLOYMENT_ENV', 'foobar')

      user_agent.reset()

      assert.same('foobar', user_agent.deployment())
    end)

    it('uses internal structure', function()
      user_agent.env.threescale_deployment_env = 'bar'

      assert.same('bar', user_agent.deployment())
    end)
  end)

  describe('.user_agent', function()
    -- User-Agent: <product> / <product-version> <comment>
    -- User-Agent: Mozilla/<version> (<system-information>) <platform> (<platform-details>) <extensions>

    it('matches common format', function()

      user_agent.env.threescale_deployment_env = 'production'

      assert.match('APIcast/' .. user_agent._VERSION, user_agent.call(), nil, true)
    end)

    it('includes system information', function()
      assert.match('(' .. user_agent.system_information() .. ')', user_agent.call())
    end)

    it('works as tostring', function()
      assert.equal(user_agent.call(), tostring(user_agent))
    end)

    it('works as function', function()
      assert.equal(user_agent.call(), user_agent())
    end)
  end)

  describe('.system_information', function()
    it('includes os information', function()
      assert.match(ffi.os ..'; ' .. ffi.arch, user_agent.system_information())
    end)

    it('includes deployment information', function()
      user_agent.env.threescale_deployment_env = 'foobar'
      assert.match(' env:foobar', user_agent.system_information())
    end)
  end)


  describe('.call', function()
    it('returns a string', function()
      stub(user_agent, 'platform').returns(nil)
      assert.equal('string', type(user_agent.call()))
    end)
  end)

end)
