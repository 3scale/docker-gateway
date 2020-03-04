use lib 't';
use Test::APIcast::Blackbox 'no_plan';

run_tests();

__DATA__

=== TEST 1: multi service configuration with path based routing
Two services can exist together and are split by their hostname and mapping rules.
--- env eval
('APICAST_PATH_ROUTING' => '1')
--- configuration
{
  "services": [
    {
      "id": 42,
      "backend_version": 1,
      "proxy": {
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/api-backend/foo/",
        "hosts": [
          "same"
        ],
        "backend_authentication_type": "service_token",
        "backend_authentication_value": "service-one",
        "proxy_rules": [
          {
            "pattern": "/one",
            "http_method": "GET",
            "metric_system_name": "one",
            "delta": 1
          }
        ]
      }
    },
    {
      "id": 21,
      "backend_version": 2,
      "proxy": {
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/api-backend/bar/",
        "hosts": [
          "same"
        ],
        "backend_authentication_type": "service_token",
        "backend_authentication_value": "service-two",
        "proxy_rules": [
          {
            "pattern": "/two",
            "http_method": "GET",
            "metric_system_name": "two",
            "delta": 2
          }
        ]
      }
    }
  ]
}
--- backend
  location /transactions/authrep.xml {
    content_by_lua_block { ngx.exit(200) }
  }
--- upstream
  location ~ /api-backend(/.+) {
     echo 'yay, api backend: $1';
  }
--- request eval
["GET /one?user_key=one-key", "GET /two?app_id=two-id&app_key=two-key"]
--- more_headers eval
["Host: same", "Host: same"]
--- response_body eval
["yay, api backend: /foo/one\x{0a}", "yay, api backend: /bar/two\x{0a}"]
--- error_code eval
[200, 200]
--- no_error_log
[error]

=== TEST 2: multi service configuration with path based routing defaults to host routing
If none of the services match it goes for the host.
--- env eval
('APICAST_PATH_ROUTING' => '1')
--- configuration
{
  "services": [
    {
      "id": 42,
      "backend_version": 1,
      "proxy": {
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/api-backend/foo/",
        "hosts": [
          "one"
        ],
        "backend_authentication_type": "service_token",
        "backend_authentication_value": "service-one",
        "error_status_no_match": 411,
        "proxy_rules": [
          {
            "pattern": "/one",
            "http_method": "GET",
            "metric_system_name": "one",
            "delta": 1
          }
        ]
      }
    },
    {
      "id": 21,
      "backend_version": 2,
      "proxy": {
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/api-backend/bar/",
        "hosts": [
          "two"
        ],
        "backend_authentication_type": "service_token",
        "backend_authentication_value": "service-two",
        "error_status_no_match": 412,
        "proxy_rules": [
          {
            "pattern": "/two",
            "http_method": "GET",
            "metric_system_name": "two",
            "delta": 2
          }
        ]
      }
    }
  ]
}
--- backend
  location /transactions/authrep.xml {
    content_by_lua_block { ngx.exit(200) }
  }
--- upstream
  location ~ /api-backend(/.+) {
     echo 'yay, api backend: $1';
  }
--- request eval
["GET /foo?user_key=uk", "GET /foo?app_id=ai&app_key=ak"]
--- more_headers eval
["Host: one", "Host: two"]
--- response_body eval
["No Mapping Rule matched", "No Mapping Rule matched"]
--- error_code eval
[411, 412]
--- no_error_log
[error]

=== TEST 3: apicast path-based routing without fallback to host-based
In this test, we define a couple of services. We make a request that does not
match any of the mapping rules defined, but the host header matches one of the
services. We define a custom "error_status_no_match" match in that service to
verify that APIcast does not fallback to host-based routing. If it did, we
would see that custom error status in the response, instead of a 404.
--- env eval
('APICAST_PATH_ROUTING_ONLY' => '1')
--- configuration
{
  "services": [
    {
      "id": 42,
      "backend_version": 1,
      "proxy": {
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/api-backend/foo/",
        "hosts": [
          "one"
        ],
        "backend_authentication_type": "service_token",
        "backend_authentication_value": "service-one",
        "error_status_no_match": 411,
        "proxy_rules": [
          {
            "pattern": "/one",
            "http_method": "GET",
            "metric_system_name": "one",
            "delta": 1
          }
        ]
      }
    },
    {
      "id": 21,
      "backend_version": 2,
      "proxy": {
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/api-backend/bar/",
        "hosts": [
          "two"
        ],
        "backend_authentication_type": "service_token",
        "backend_authentication_value": "service-two",
        "error_status_no_match": 412,
        "proxy_rules": [
          {
            "pattern": "/two",
            "http_method": "GET",
            "metric_system_name": "two",
            "delta": 2
          }
        ]
      }
    }
  ]
}
--- backend
  location /transactions/authrep.xml {
    content_by_lua_block { ngx.exit(200) }
  }
--- upstream
  location ~ /api-backend(/.+) {
     echo 'yay, api backend: $1';
  }
--- request
GET /do_not_match?user_key=uk
--- more_headers
Host: one
--- error_code: 404
--- no_error_log
[error]

=== TEST 4: multi service configuration with path based routing and special chars (spaces)
--- env eval
('APICAST_PATH_ROUTING' => '1')
--- configuration
{
  "services": [
    {
      "id": 42,
      "backend_version": 1,
      "proxy": {
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/api-backend/foo/",
        "hosts": [
          "same"
        ],
        "backend_authentication_type": "service_token",
        "backend_authentication_value": "service-one",
        "proxy_rules": [
          {
            "pattern": "/one/{test}",
            "http_method": "GET",
            "metric_system_name": "one",
            "delta": 1
          }
        ]
      }
    },
    {
      "id": 21,
      "backend_version": 2,
      "proxy": {
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/api-backend/bar/",
        "hosts": [
          "same"
        ],
        "backend_authentication_type": "service_token",
        "backend_authentication_value": "service-two",
        "proxy_rules": [
          {
            "pattern": "/two/%20two",
            "http_method": "GET",
            "metric_system_name": "two",
            "delta": 2
          },
          {
            "pattern": "/two/%20two/test",
            "http_method": "GET",
            "metric_system_name": "two",
            "delta": 2
          }
        ]
      }
    }
  ]
}
--- backend
  location /transactions/authrep.xml {
    content_by_lua_block { ngx.exit(200) }
  }
--- upstream
  location ~ /api-backend(/.+) {
     echo 'yay, api backend: $1';
  }
--- request eval
[
  "GET /one/12%2012?user_key=one-key",
  "GET /two/%20two?app_id=two-id&app_key=two-key",
  "GET /two/%20two/test?app_id=two-id&app_key=two-key"
]
--- more_headers eval
["Host: same", "Host: same", "Host: same"]
--- response_body eval
[
  "yay, api backend: /foo/one/12 12\x{0a}",
  "yay, api backend: /bar/two/ two\x{0a}",
  "yay, api backend: /bar/two/ two/test\x{0a}"
]
--- error_code eval
[200, 200, 200]
--- no_error_log
[error]
