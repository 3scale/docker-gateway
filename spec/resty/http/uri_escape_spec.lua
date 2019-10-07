local escape = require("resty.http.uri_escape")

describe('resty.http.uri_escape', function()

  it("escapes uri correctly", function()
    local test_cases = {
      {"/foo /test", "/foo%20/test"},
      {"/foo/test", "/foo/test"},
      {"/foo/", "/foo/"},
      {"/foo / test", "/foo%20/%20test"},
      {"/foo    /  test", "/foo%20%20%20%20/%20%20test"},
      {"/foo#/test", "/foo%23/test"},
      {"/foo$/test", "/foo$/test"},
      {"/foo=/test", "/foo=/test"},
      {"/foo!/test", "/foo!/test"} ,
      {"/foo,/test", "/foo,/test"},
    }

    for _,val in ipairs(test_cases) do
      assert.are.same(escape.escape_uri(val[1]), val[2])
    end
  end)
end)
