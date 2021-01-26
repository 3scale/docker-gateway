local client_ip = require('apicast.policy.ip_check.client_ip')

describe('ClientIP', function()
  describe('.get_from', function()
    describe('when the source is the last caller IP', function()
      it('returns the IP in ngx.var.remote_addr', function()
        ngx.var = { remote_addr = '1.2.3.4' }

        local ip = client_ip.get_from({ 'last_caller' })

        assert.equals('1.2.3.4', ip)
      end)
    end)

    describe('when the source is the X-Real-IP header', function()
      describe('and the header is set', function()
        it('returns the IP in the header', function()
          stub(ngx.req, 'get_headers', function()
            return { ["X-Real-IP"] = '1.2.3.4' }
          end)

          local ip = client_ip.get_from({ 'X-Real-IP' })

          assert.equals('1.2.3.4', ip)
        end)
      end)

      describe('and the header is not set', function()
        it('returns nil', function()
          stub(ngx.req, 'get_headers', function() return { } end)

          local ip = client_ip.get_from({ 'X-Real-IP' })

          assert.is_nil(ip)
        end)
      end)
    end)

    describe('when the source is the X-Forwarded-For header', function()
      describe('and the header contains several IPs', function()
        it('returns the first one', function()
          stub(ngx.req, 'get_headers', function()
            return { ["X-Forwarded-For"] = '1.2.3.4, 5.6.7.8' }
          end)

          local ip = client_ip.get_from({ 'X-Forwarded-For' })

          assert.equals('1.2.3.4', ip)
        end)
      end)

      describe('and the header contains one IP', function()
        it('returns it', function()
          stub(ngx.req, 'get_headers', function()
            return { ["X-Forwarded-For"] = '1.2.3.4' }
          end)

          local ip = client_ip.get_from({ 'X-Forwarded-For' })

          assert.equals('1.2.3.4', ip)
        end)
      end)

      describe('and the header is not set', function()
        it('returns nil', function()
          stub(ngx.req, 'get_headers', function() return { } end)

          local ip = client_ip.get_from({ 'X-Forwarded-For' })

          assert.is_nil(ip)
        end)
      end)

      describe('and the host contains port', function()

        it("returns valid IPv4 address", function()
          stub(ngx.req, 'get_headers', function()
            return { ["X-Forwarded-For"] = '1.2.3.4:1000' }
          end)

          local ip = client_ip.get_from({ 'X-Forwarded-For' })

          assert.equals('1.2.3.4', ip)
        end)

        it("with invalid port", function()
          stub(ngx.req, 'get_headers', function()
            return { ["X-Forwarded-For"] = '1.2.3.4:foo' }
          end)

          local ip = client_ip.get_from({ 'X-Forwarded-For' })

          assert.equals('1.2.3.4', ip)
        end)

        it("with port out of range", function()
          stub(ngx.req, 'get_headers', function()
            return { ["X-Forwarded-For"] = '1.2.3.4:99999' }
          end)

          local ip = client_ip.get_from({ 'X-Forwarded-For' })

          assert.equals('1.2.3.4', ip)
        end)

        it("returns valid IPv6 address", function()

          stub(ngx.req, 'get_headers', function()
            return { ["X-Forwarded-For"] = '[2001:4860:4860::8888]:8080' }
          end)

          local ip = client_ip.get_from({ 'X-Forwarded-For' })

          assert.equals('[2001:4860:4860::8888]', ip)
        end)

      end)
    end)

    describe('when the source is the proxy_protocol_addr variable', function()
      it('returns the IP in ngx.var.proxy_protocol_addr', function()
        ngx.var = { proxy_protocol_addr = '1.2.3.4' }

        local ip = client_ip.get_from({ 'proxy_protocol_addr' })

        assert.equals('1.2.3.4', ip)
      end)
    end)

    describe('when no source is given', function()
      it('returns nil', function()
        local ip = client_ip.get_from({})

        assert.is_nil(ip)
      end)
    end)

    describe('when sources is nil', function()
      it('returns nil', function()
        local ip = client_ip.get_from()

        assert.is_nil(ip)
      end)
    end)

    describe('when an invalid source is given', function()
      it('returns nil', function()
        local ip = client_ip.get_from({ 'invalid' })

        assert.is_nil(ip)
      end)
    end)

    describe('when multiple sources are given', function()
      it('returns the value of the first one set', function()
        stub(ngx.req, 'get_headers', function()
          return { ["X-Forwarded-For"] = '1.2.3.4' }
        end)

        local ip = client_ip.get_from(
          { 'X-Real-IP', 'X-Forwarded-For', 'last_caller' }
        )

        assert.equals('1.2.3.4', ip)
      end)
    end)

    -- Because of a limitation in how the schema needs to be written to be
    -- rendered correctly, there might be duplicated sources.
    describe('when there are duplicated sources', function()
      it('returns the value of the first one set', function()
        stub(ngx.req, 'get_headers', function()
          return { ["X-Forwarded-For"] = '1.2.3.4' }
        end)

        -- Notice that "X-Forwarded-For" is duplicated
        local ip = client_ip.get_from(
          { 'X-Real-IP', 'X-Forwarded-For', 'X-Forwarded-For' }
        )

        assert.equals('1.2.3.4', ip)
      end)
    end)
  end)
end)
