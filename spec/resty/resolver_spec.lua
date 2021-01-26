local resty_resolver = require 'resty.resolver'
local resolver_cache = require 'resty.resolver.cache'

describe('resty.resolver', function()

  -- TODO: consider :new(self) self api like resty.dns.resolver
  describe('.new', function()
    local new = resty_resolver.new

    it('accepts dns', function()
      local dns = { 'dns resolver' }
      local r = new(dns)

      assert.equal(dns, r.dns)
    end)

    it('populates options', function()
      local dns = { TYPE_A = 1 }

      local r = new(dns)

      assert.same({qtype = 1 }, r.options)
    end)
  end)

  describe(':get_servers', function()
    local dns, resolver

    before_each(function()
      dns = {
        query = spy.new(function(_, name)
          return {
            { name = name , address = '127.0.0.1' }
          }
        end)
      }
      resolver = resty_resolver.new(dns, { cache = resolver_cache.new() })
    end)

    it('returns servers', function()
      dns.query = spy.new(function()
        return {
          { name = '3scale.net' , address = '127.0.0.1' }
        }
      end)
      resolver.options = { qtype = 'A' }

      local servers, err = resolver:get_servers('3scale.net')

      assert.falsy(err)
      assert.equal(1, #servers)
      assert.spy(dns.query).was.called_with(dns, '3scale.net.', { qtype = 'A' })
    end)

    it('skips answers with no address', function()
      dns.query = spy.new(function()
        return {
          { name = 'www.3scale.net' , cname = '3scale.net' },
          { name = '3scale.net' , address = '127.0.0.1' }
        }
      end)

      local servers, err = resolver:get_servers('www.3scale.net')

      assert.falsy(err)
      assert.equal(1, #servers)
      assert.spy(dns.query).was.called_with(dns, 'www.3scale.net.', {})
    end)

    it('searches domains', function()
      dns.query = spy.new(function(_, qname)
        if qname == '3scale.net' then
          return {
            { name = '3scale.net' , address = '127.0.0.1' }
          }
        else
          return { errcode = 3, errstr = 'name error' }
        end
      end)
      resolver.options = { qtype = 'A' }
      resolver.search = { '', 'example.com', 'net' }

      local servers, err = resolver:get_servers('3scale')

      assert.falsy(err)
      assert.equal(1, #servers)
      assert.spy(dns.query).was.called_with(dns, '3scale.', resolver.options)
      assert.spy(dns.query).was.called_with(dns, '3scale.example.com', resolver.options)
      assert.spy(dns.query).was.called_with(dns, '3scale.net', resolver.options)
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

  describe('.search', function()
    it('contains empty scope', function ()

      assert.same({''}, resty_resolver.search)
    end)
  end)

  describe(':lookup', function()
    local  resolver

    before_each(function()
      local dns = {
        query = spy.new(function(_, name)
          return {
            { name = name , address = '127.0.0.1' }
          }
        end)
      }
      resolver = resty_resolver.new(dns, { cache = resolver_cache.new(), search = {"foo.com"}})
    end)

    it("works when fully qualified name in private base_url", function()
      local answer, err = resolver:lookup('test.service.ns.cluster.local.')
      assert.same("test.service.ns.cluster.local", answer[1].name)
      assert.same(err, nil)
    end)

    it("search domain is appended correctly", function()
      local answer, err = resolver:lookup('test.service.ns.cluster.local')
      assert.same("test.service.ns.cluster.local.foo.com", answer[1].name)
      assert.same(err, nil)
    end)

  end)

  describe('.parse_resolver', function()

    it("handles invalid data", function()
      assert.same({'foobar', 'invalid address'}, { resty_resolver.parse_resolver('foobar') })
    end)

    it("handles missing data", function()
      assert.same({}, { resty_resolver.parse_resolver() })
    end)

    it("parses ipv4 without port", function()
      assert.same({'192.168.0.1', 53}, resty_resolver.parse_resolver('192.168.0.1'))
    end)

    it("parses ipv4 with port", function()
      assert.same({'192.168.0.1', '5353'}, resty_resolver.parse_resolver('192.168.0.1:5353'))
    end)

    it("parses ipv6 without port", function()
      assert.same({'[dead::beef:5353]', 53}, resty_resolver.parse_resolver('dead::beef:5353'))
    end)

    it("parses ipv6 with port", function()
      assert.same({'[dead::beef]', '5353'}, resty_resolver.parse_resolver('[dead::beef]:5353'))
    end)
  end)

  describe('.parse_nameservers', function()
    local tmpname
    local resty_env = require('resty.env')

    before_each(function()
      tmpname = io.tmpfile()

      tmpname:write([[
search localdomain.example.com local
nameserver 127.0.0.2
nameserver 127.0.0.1
]])
    end)

    it('returns nameserver tuples', function()
      local nameservers = resty_resolver.parse_nameservers(tmpname)

      assert.equal(2, #nameservers)
      assert.same({ '127.0.0.2', 53 }, nameservers[1])
      assert.same({ '127.0.0.1', 53 }, nameservers[2])
    end)

    it('returns nameserver tuples ignoring commentaries', function()

      local resolvconf = io.tmpfile()

      resolvconf:write([[
# nameserver updated  in comentary
#nameserver updated  in comentary
#comentary nameserver 1.2.3.4
#comentary nameserver
# search updated.example.com  in comentary
#search updated  in comentary
#search nameserver 1.2.3.4
#search nameserver
search localdomain.example.com local
nameserver 127.0.0.2
nameserver 127.0.0.1
]])

      local nameservers = resty_resolver.parse_nameservers(resolvconf)

      assert.equal(2, #nameservers)
      assert.same({ '127.0.0.2', 53 },  nameservers[1])
      assert.same({ '127.0.0.1', 53 }, nameservers[2])
    end)

    it('returns nameserver touples ignoring commentaries after nameserver and search', function()

      local resolvconf = io.tmpfile()

      resolvconf:write([[
search localdomain.example.com local #search nameserver
nameserver 127.0.0.2 #search nameserver
nameserver 127.0.0.1 # nameserver search
]])

      local nameservers = resty_resolver.parse_nameservers(resolvconf)

      assert.equal(2, #nameservers)
      assert.same({ '127.0.0.2', 53 },  nameservers[1])
      assert.same({ '127.0.0.1', 53 }, nameservers[2])
    end)

    it('do not replicates nameservers from resolver env var', function()
      resty_env.set('RESOLVER', '127.0.0.1')
      local nameservers = resty_resolver.parse_nameservers(tmpname)

      assert.equal(2, #nameservers)
      assert.same({ '127.0.0.1', 53 }, nameservers[1])
      assert.same({ '127.0.0.2', 53 }, nameservers[2])
    end)

    it('returns search domains', function()
      local search = resty_resolver.parse_nameservers(tmpname).search

      assert.equal(2, #search)
      assert.same({ 'localdomain.example.com', 'local' },  search)
    end)

    it('ignores invalid RESOLVER', function()
      resty_env.set('RESOLVER', 'invalid-nameserver')

      local nameservers = resty_resolver.parse_nameservers('')

      assert.equal(0, #nameservers)
    end)

    it('uses correct RESOLVER', function()
      resty_env.set('RESOLVER', '192.168.0.1:53')

      local nameservers = resty_resolver.parse_nameservers('')

      assert.equal(1, #nameservers)
      assert.same({'192.168.0.1', '53'}, nameservers[1])
    end)
  end)

end)
