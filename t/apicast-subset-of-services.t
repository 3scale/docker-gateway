use Test::APIcast::Blackbox 'no_plan';

run_tests();

__DATA__

=== TEST 1: multi service configuration limited to specific service
--- env eval
("APICAST_SERVICES_LIST", "42,21")
--- configuration
{
  "services": [
    {
      "backend_version": 1,
      "proxy": {
        "hosts": [
          "one"
        ],
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/",
        "proxy_rules": [
          {
            "http_method": "GET",
            "delta": 1,
            "metric_system_name": "one",
            "pattern": "/"
          }
        ]
      },
      "id": 42
    },
    {
      "proxy": {
        "hosts": [
          "two"
        ]
      },
      "id": 11
    }
  ]
}
--- backend
  location /transactions/authrep.xml {
    content_by_lua_block { ngx.exit(200) }
  }
--- upstream
  location ~ / {
     echo 'yay, api backend';
  }
--- pipelined_requests eval
["GET /?user_key=1","GET /?user_key=2"]
--- more_headers eval
["Host: one", "Host: two"]
--- response_body eval
["yay, api backend\n", ""]
--- error_code eval
[200, 404]
