local IpCheckPolicy = require('apicast.policy.ip_check')
local ClientIP = require('apicast.policy.ip_check.client_ip')
local iputils = require("resty.iputils")

describe('IP Check policy', function()
  before_each(function()
    stub(ngx, 'say')
    stub(ngx, 'exit')
  end)

  describe('.new', function()
    it('ignores invalid whitelist IPs', function()
      local ip_check = IpCheckPolicy.new(
        {
          ips = { '256.256.256.256/28', '1.2.3.4' },
          check_type = 'whitelist'
        }
      )

      assert.same(iputils.parse_cidrs({ '1.2.3.4' }), ip_check.ips)
    end)

    it('ignores invalid blacklist IPs', function()
      local ip_check = IpCheckPolicy.new(
        {
          ips = { '256.256.256.256/28', '1.2.3.4' },
          check_type = 'blacklist'
        }
      )

      assert.same(iputils.parse_cidrs({ '1.2.3.4' }), ip_check.ips)
    end)
  end)

  describe('.access', function()
    describe('when there are blacklisted IPs', function()
      local ip_check = IpCheckPolicy.new(
        {
          ips = { '1.2.3.0/28', '2.3.4.0/28', '3.4.5.6' },
          check_type = 'blacklist'
        }
      )

      it('denies the request when the IP is in one of the CIDRs', function()
        stub(ClientIP, 'get_from', function() return '2.3.4.1' end)

        ip_check:access()

        assert.stub(ngx.exit).was_called_with(ngx.HTTP_FORBIDDEN)
      end)

      it('denies the request when the IP is among them', function()
        stub(ClientIP, 'get_from', function() return '3.4.5.6' end)

        ip_check:access()

        assert.stub(ngx.exit).was_called_with(ngx.HTTP_FORBIDDEN)
      end)

      it('does not deny the request when the IP is not among them', function()
        stub(ClientIP, 'get_from', function() return '3.3.3.3' end)

        ip_check:access()

        assert.stub(ngx.exit).was_not_called()
      end)
    end)

    describe('when there are whitelisted IPs', function()
      local ip_check = IpCheckPolicy.new(
        {
          ips = { '1.2.3.0/28', '2.3.4.0/28', '3.4.5.6' },
          check_type = 'whitelist'
        }
      )

      it('denies the requests when the IP is not among them', function()
        stub(ClientIP, 'get_from', function() return '3.3.3.3' end)

        ip_check:access()

        assert.stub(ngx.exit).was_called_with(ngx.HTTP_FORBIDDEN)
      end)

      it('does not deny the request when the IP is in one of the CIDRs', function()
        stub(ClientIP, 'get_from', function() return '2.3.4.1' end)

        ip_check:access()

        assert.stub(ngx.exit).was_not_called()
      end)

      it('does not deny the request when the IP is among them', function()
        stub(ClientIP, 'get_from', function() return '3.4.5.6' end)

        ip_check:access()

        assert.stub(ngx.exit).was_not_called()
      end)
    end)

    describe('when an error msg is not provided', function()
      it('returns the default one when the request is denied', function()
        local ip = '1.2.3.4'
        stub(ClientIP, 'get_from', function() return ip end)
        local ip_check = IpCheckPolicy.new(
          { ips = { ip }, check_type = 'blacklist' }
        )

        ip_check:access()

        assert.stub(ngx.say).was_called_with('IP address not allowed')
      end)
    end)

    describe('when an error msg is provided', function()
      it('returns it when the request is denied', function()
        local err_msg = 'A custom error msg'
        local ip = '1.2.3.4'
        stub(ClientIP, 'get_from', function() return ip end)
        local ip_check = IpCheckPolicy.new(
          { ips = { ip }, check_type = 'blacklist', error_msg = err_msg }
        )

        ip_check:access()

        assert.stub(ngx.say).was_called_with(err_msg)
      end)
    end)

    describe('when the client IP cannot be obtained', function()
      it('does not deny the request', function()
        stub(ClientIP, 'get_from', function() return nil end)
        local ip_check = IpCheckPolicy.new(
          { ips = { '1.2.3.4' }, check_type = 'blacklist' }
        )

        ip_check:access()

        assert.stub(ngx.exit).was_not_called()
      end)
    end)
  end)
end)
