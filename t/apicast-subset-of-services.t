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



=== TEST 2: multi service configuration limited with Regexp Filter
--- env eval
("APICAST_SERVICES_FILTER_BY_URL", "^on*")
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

=== TEST 3: multi service configuration limited with Regexp Filter and service list
--- env eval
(
"APICAST_SERVICES_FILTER_BY_URL", "^on*",
"APICAST_SERVICES_LIST", "21"
)
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
      "backend_version": 1,
      "proxy": {
        "hosts": [
          "two"
        ],
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/two",
        "proxy_rules": [
          {
            "http_method": "GET",
            "delta": 1,
            "metric_system_name": "one",
            "pattern": "/"
          }
        ]
      },
      "id": 21
    },
    {
      "proxy": {
        "hosts": [
          "three"
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
  location / {
     echo 'yay, api backend';
  }

  location /two {
     echo 'yay, api backend two';
  }

--- pipelined_requests eval
["GET /?user_key=1","GET /?user_key=2", "GET /?user_key=3"]
--- more_headers eval
["Host: one", "Host: two", "Host: three"]
--- response_body eval
["yay, api backend\n", "yay, api backend two\n", ""]
--- error_code eval
[200, 200, 404]
