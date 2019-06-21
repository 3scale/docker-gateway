local cjson = require('cjson')

local configuration = cjson.encode(cjson.decode([[{
  "services": [
    {
      "proxy": {
        "hosts": [
          "localhost",
          "127.0.0.1"
        ],
        "policy_chain": [
          { "name": "apicast.policy.echo" }
        ]
      }
    }
  ]
}
]]))

-- See https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/Data_URIs
local function data_url(mime_type, content)
  return string.format([[data:%s,%s]],mime_type, ngx.escape_uri(content))
end

return {
    worker_processes = '1',
    master_process = 'off',
    lua_code_cache = 'on',
    configuration_loader = 'lazy',
    configuration_cache = 0,
    configuration = context.configuration or os.getenv('APICAST_CONFIGURATION') or data_url('application/json', configuration),
    port = { metrics = 9421 }, -- see https://github.com/prometheus/prometheus/wiki/Default-port-allocations,
    timer_resolution = false,
}
