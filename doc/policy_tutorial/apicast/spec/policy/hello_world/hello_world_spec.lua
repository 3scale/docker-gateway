local _M = require('apicast.policy.hello_world')

describe('hello_world policy', function()
  describe('.new', function()
    it('works without configuration', function()
      assert(_M.new())
    end)

    it('accepts configuration', function()
        assert(_M.new({ overwrite = false, secret = "mysecret"}))
    end)
  end)

  describe('rewrite with overwrite', function()
    local config = { overwrite = true, secret = "mysecret" }

    local ngx_req_params = {}
    local ngx_req_headers = {}
    local context = {}

    before_each(function()

      stub(ngx.req,'get_headers', function()
        return ngx_req_headers
      end)

      stub(ngx.req, 'set_header', function(name, value)
        ngx_req_headers[name] = value
      end)

      stub(ngx.req, 'get_uri_args', function()
        return ngx_req_params
      end)
    end)

    it('test single param', function()
      local hello_world_policy = _M.new(config)

      --create the test request
      ngx_req_params["testkey"] = 'testvalue'

      --execute the policy function
      hello_world_policy:rewrite(context)

      --retrieve the http header and verify the content
      local responseheader = ngx.req.get_headers()["testkey"]
      assert.same("testvalue", responseheader)

    end)

    it('test overwrite header', function()
      local hello_world_policy = _M.new(config)

      --create the test request
      ngx_req_params["testkey"] = 'testvalue'
      ngx_req_headers["testkey"] = 'myheader'

      --execute the policy function
      hello_world_policy:rewrite(context)

      --retrieve the http header and verify the content
      local responseheader = ngx.req.get_headers()["testkey"]
      assert.same("testvalue", responseheader)

    end)

    it('test multiple params', function()
      local hello_world_policy = _M.new(config)

      --create test request
      ngx_req_params["param1"] = "value1"
      ngx_req_params["param2"] = "value2"

      --execute the policy function
      hello_world_policy:rewrite(context)

      --retrieve the http headers and verify the content
      local header1 = ngx.req.get_headers()["param1"]
      local header2 = ngx.req.get_headers()["param2"]
      assert.same("value1", header1)
      assert.same("value2", header2)

    end)

  end)

  describe('rewrite without overwrite',function()
    local config = { overwrite = false, secret = "mysecret" }

    local ngx_req_params = {}
    local ngx_req_headers = {}

    local context = {}

    before_each(function()

      stub(ngx.req,'get_headers', function()
        return ngx_req_headers
      end)

      stub(ngx.req, 'set_header', function(name, value)
        ngx_req_headers[name] = value
      end)

      stub(ngx.req, 'get_uri_args', function()
        return ngx_req_params
      end)

    end)

    it('test with single param', function()
      local hello_world_policy = _M.new(config)

      --create the test request
      ngx_req_params["testkey"] = 'testvalue'
      ngx_req_headers["testkey"] = 'myheader'

      --execute the policy function
      hello_world_policy:rewrite(context)

      --retrieve the http header and verify the content
      local responseheader = ngx.req.get_headers()["testkey"]
      assert.same("myheader", responseheader)
    end)

  end)

  describe('secret header test', function()
    local config = {secret = "mysecret" }
    local ngx_req_headers = {}
    local ngx_req_params = {}

    local context = {}

    before_each(function()
      stub(ngx.req,'get_headers', function()
        return ngx_req_headers
      end)

      stub(ngx.req, 'set_header', function(name, value)
        ngx_req_headers[name] = value
      end)

      stub(ngx.req, 'get_uri_args', function()
        return ngx_req_params
      end)
    end)

    it('authorized', function()
      local hello_world_policy = _M.new(config)

      ngx_req_headers["secret"] = "mysecret"

      hello_world_policy:rewrite(context)
      hello_world_policy:access(context)
    end)

    it('not authorized', function()
      local hello_world_policy = _M.new(config)

      ngx_req_headers["secret"] = "myownsecret"

      hello_world_policy:rewrite(context)
      hello_world_policy:access(context)

      assert.same(ngx.status, 403)
    end)

  end)
end)
