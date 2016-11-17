local resty_resolver = require 'resty.resolver'

describe('resty.resolver', function()

  -- TODO: consider :new(self) self api like resty.dns.resolver
  describe('.new', function()
    local new = resty_resolver.new

    it('accepts dns', function()
      local dns = { 'dns resolver' }
      local r = new(dns)

      assert.equal(dns, r.dns)
    end)
  end)

  describe(':get_servers', function()
    local dns = { }
    local resolver = resty_resolver.new(dns)

    it('returns servers', function()
      dns.TYPE_A = 1
      dns.query = spy.new(function()
        return {
          { name = '3scale.net' , address = '127.0.0.1' }
        }
      end)

      local servers, err = resolver:get_servers('3scale.net')

      assert.falsy(err)
      assert.equal(1, #servers)
      assert.spy(dns.query).was.called_with(dns, '3scale.net', { qtype = 1 })
    end)

    it('returns servers for ip', function()
      local answer = { address = '127.0.0.2', ttl = -1 }

      local servers, err = resolver:get_servers('127.0.0.2')

      assert.falsy(err)
      assert.same({ answer, answers = { answer }, query = '127.0.0.2' }, servers)
    end)

    it('accepts port', function()
      dns.query = function() return { {address = '127.0.0.2'} } end

      local servers, err = resolver:get_servers('localhost', { port = 1337 })
      local server, _ = unpack(servers or {})

      assert.falsy(err)
      assert.truthy(server)
      assert.equal(1337, server.port)
      assert.equal('127.0.0.2', server.address)
    end)

    it('returns back the query', function()
      local answer, err = resolver:get_servers('example.com')

      assert.falsy(err)
      assert.equal('example.com', answer.query)
    end)
  end)

  describe('.parse_nameservers', function()
    local tmpname = io.tmpfile()

    tmpname:write('nameserver 127.0.0.2\n')
    tmpname:write('nameserver 127.0.0.1\n')

    it('returns nameserver touples', function()
      local nameservers = resty_resolver.parse_nameservers(tmpname)

      assert.equal(2, #nameservers)
      assert.same({ {'127.0.0.2' }, { '127.0.0.1' } }, nameservers)
    end)

  end)

end)
