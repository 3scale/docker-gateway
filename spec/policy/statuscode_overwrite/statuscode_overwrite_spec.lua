local StatusCodeOverwrite = require('apicast.policy.statuscode_overwrite')

describe('Status Codes overwrite policy', function()

  it('mapped correctly valid status code', function()
      local policy = StatusCodeOverwrite.new({
        http_statuses = {
          { upstream=200, apicast=201 }
        }
      })

      ngx.status = 200
      policy:header_filter()
      assert.same(ngx.status, 201)

      ngx.status = 403
      policy:header_filter()
      assert.same(ngx.status, 403)

  end)

  it('invalid code fails correctly', function()
    assert.has_error(function()
      return StatusCodeOverwrite.new({
        http_statuses = {
          { upstream=1, apicast=201 }
        }})
      end)

  end)


  it('Upstream code is not defined', function()
    assert.has_error(function()
      return StatusCodeOverwrite.new({
        http_statuses = {
          { apicast=201 }
        }})
      end)
  end)

  it('Apicast code is not defined', function()
    assert.has_error(function()
      return StatusCodeOverwrite.new({
        http_statuses = {
          { upstream=201 }
        }})
      end)
  end)

end)
