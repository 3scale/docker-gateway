use lib 't';
use Test::APIcast::Blackbox 'no_plan';

# Can't run twice because of the report/limits/etc..
repeat_each(1);

run_tests();

__DATA__

=== TEST 1: Simple connection
--- configuration
{
  "services": [
    {
      "id": 42,
      "backend_version":  1,
      "backend_authentication_type": "service_token",
      "backend_authentication_value": "token-value",
      "proxy": {
        "hosts": [
          "localhost"
        ],
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/",
        "proxy_rules": [
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 1 }
        ],
        "policy_chain": [
          {
            "name": "apicast.policy.rate_limit_headers"
          },
          {
            "name": "apicast",
            "version": "builtin",
            "configuration": {}
          }
        ]
      }
    }
  ]
}
--- backend
location /transactions/authrep.xml {
  content_by_lua_block {
    ngx.header["3scale-Limit-Max-Value"] = 10
    ngx.header["3scale-Limit-Remaining"] = 9
    ngx.header["3scale-Limit-Reset"] = 60
    ngx.exit(200)
  }
}
--- upstream env
location / {
  access_by_lua_block {
      ngx.say("OK")
  }
}

--- request
GET /?user_key=123
--- response_headers
RateLimit-Limit: 10
RateLimit-Remaining: 9
RateLimit-Reset: 60
--- response_body env
OK
--- error_code: 200
--- no_error_log
[error]


=== TEST 2: different usage metrics
--- configuration
{
  "services": [
    {
      "id": 42,
      "backend_version":  1,
      "backend_authentication_type": "service_token",
      "backend_authentication_value": "token-value",
      "proxy": {
        "hosts": [
          "localhost"
        ],
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/",
        "proxy_rules": [
          { "pattern": "/foo", "http_method": "GET", "metric_system_name": "foo", "delta": 1 },
          { "pattern": "/bar", "http_method": "GET", "metric_system_name": "bar", "delta": 1 }
        ],
        "policy_chain": [
          {
            "name": "apicast.policy.rate_limit_headers"
          },
          {
            "name": "apicast",
            "version": "builtin",
            "configuration": {}
          }
        ]
      }
    }
  ]
}
--- backend
location /transactions/authrep.xml {
  content_by_lua_block {
    if ngx.var.arg_user_key == "foo" then
        ngx.header["3scale-Limit-Max-Value"] = 10
        ngx.header["3scale-Limit-Remaining"] = 9
        ngx.header["3scale-Limit-Reset"] = 60
    else
        ngx.header["3scale-Limit-Max-Value"] = 100
        ngx.header["3scale-Limit-Remaining"] = 99
        ngx.header["3scale-Limit-Reset"] = 60
    end
    ngx.exit(200)
  }
}
--- upstream env
location / {
  access_by_lua_block {
      ngx.say("OK")
  }
}

--- request eval
["GET /foo?user_key=foo", "GET /bar?user_key=bar"]
--- response_headers_like eval
[
"RateLimit-Limit: 10\n" .
    "RateLimit-Remaining: 9\n".
    "RateLimit-Reset: [56]\\d\n",
"RateLimit-Limit: 100\n" .
    "RateLimit-Remaining: 99\n".
    "RateLimit-Reset: [56]\\d\n",
]
--- response_body eval
["OK\n", "OK\n"]
--- error_code eval
[200, 200]
--- no_error_log
[error]


=== TEST 3: second request is sending the information
--- configuration
{
  "services": [
    {
      "id": 42,
      "backend_version":  1,
      "backend_authentication_type": "service_token",
      "backend_authentication_value": "token-value",
      "proxy": {
        "hosts": [
          "localhost"
        ],
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/",
        "proxy_rules": [
          { "pattern": "/foo", "http_method": "GET", "metric_system_name": "foo", "delta": 1 }
        ],
        "policy_chain": [
          {
            "name": "apicast.policy.rate_limit_headers"
          },
          {
            "name": "apicast",
            "version": "builtin",
            "configuration": {}
          }
        ]
      }
    }
  ]
}
--- backend
location /transactions/authrep.xml {
  content_by_lua_block {
    ngx.header["3scale-Limit-Max-Value"] = 10
    ngx.header["3scale-Limit-Remaining"] = 9
    ngx.header["3scale-Limit-Reset"] = 60
    ngx.exit(200)
  }
}
--- upstream env
location / {
  access_by_lua_block {
      ngx.say("OK")
  }
}

--- request eval
["GET /foo?user_key=foo", "GET /foo?user_key=foo"]
--- response_headers eval
--- response_headers_like eval
[
"RateLimit-Limit: 10\n" .
    "RateLimit-Remaining: 9\n".
    "RateLimit-Reset: [56]\\d\n",
"RateLimit-Limit: 10\n" .
    "RateLimit-Remaining: 8\n".
    "RateLimit-Reset: [56]\\d\n"
]
--- response_body eval
["OK\n", "OK\n"]
--- error_code eval
[200, 200]
--- no_error_log
[error]


=== TEST 4: Multiple metrics in usage
--- configuration
{
  "services": [
    {
      "id": 42,
      "backend_version":  1,
      "backend_authentication_type": "service_token",
      "backend_authentication_value": "token-value",
      "proxy": {
        "hosts": [
          "localhost"
        ],
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/",
        "proxy_rules": [
          { "pattern": "/foo", "http_method": "GET", "metric_system_name": "foo", "delta": 1 },
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 2 }
        ],
        "policy_chain": [
          {
            "name": "apicast.policy.rate_limit_headers"
          },
          {
            "name": "apicast",
            "version": "builtin",
            "configuration": {}
          }
        ]
      }
    }
  ]
}
--- backend
location /transactions/authrep.xml {
  content_by_lua_block {
    ngx.header["3scale-Limit-Max-Value"] = 10
    ngx.header["3scale-Limit-Remaining"] = 9
    ngx.header["3scale-Limit-Reset"] = 60
    ngx.exit(200)
  }
}
--- upstream env
location / {
  access_by_lua_block {
      ngx.say("OK")
  }
}

--- request eval
["GET /foo?user_key=foo", "GET /foo?user_key=foo"]
--- response_headers eval
--- response_headers_like eval
[
"RateLimit-Limit: 10\n" .
    "RateLimit-Remaining: 9\n".
    "RateLimit-Reset: [56]\\d\n",
"RateLimit-Limit: 10\n" .
    "RateLimit-Remaining: 8\n".
    "RateLimit-Reset: [56]\\d\n"
]
--- response_body eval
["OK\n", "OK\n"]
--- error_code eval
[200, 200]
--- no_error_log
[error]


=== TEST 6: Test that batcher policy is working correctly
--- configuration
{
  "services": [
    {
      "id": 42,
      "backend_version":  1,
      "backend_authentication_type": "service_token",
      "backend_authentication_value": "token-value",
      "proxy": {
        "hosts": [
          "localhost"
        ],
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/",
        "proxy_rules": [
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 1 }
        ],
        "policy_chain": [
          {
            "name": "apicast.policy.rate_limit_headers"
          },
          {
            "name": "apicast.policy.3scale_batcher",
            "configuration": {
              "batch_report_seconds" : 1
            }
          },
          {
            "name": "apicast",
            "version": "builtin",
            "configuration": {}
          }
        ]
      }
    }
  ]
}
--- backend
location /transactions/authorize.xml {
  content_by_lua_block {
    ngx.header["3scale-Limit-Max-Value"] = 10
    ngx.header["3scale-Limit-Remaining"] = 9
    ngx.header["3scale-Limit-Reset"] = 60
    ngx.exit(200)
  }
}
--- upstream env
location / {
  access_by_lua_block {
      ngx.say("OK")
  }
}
--- request eval
["GET /foo?user_key=foo", "GET /foo?user_key=foo"]
--- response_headers eval
--- response_headers_like eval
[
"RateLimit-Limit: 10\n" .
    "RateLimit-Remaining: 9\n".
    "RateLimit-Reset: [56]\\d\n",
"RateLimit-Limit: 10\n" .
    "RateLimit-Remaining: 8\n".
    "RateLimit-Reset: [56]\\d\n"
]
--- response_body eval
["OK\n", "OK\n"]
--- error_code eval
[200, 200]
--- no_error_log
[error]

=== TEST 7: No rate-limit information if no limits by app
--- configuration
{
  "services": [
    {
      "id": 42,
      "backend_version":  1,
      "backend_authentication_type": "service_token",
      "backend_authentication_value": "token-value",
      "proxy": {
        "hosts": [
          "localhost"
        ],
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/",
        "proxy_rules": [
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 1 }
        ],
        "policy_chain": [
          {
            "name": "apicast.policy.rate_limit_headers"
          },
          {
            "name": "apicast",
            "version": "builtin",
            "configuration": {}
          }
        ]
      }
    }
  ]
}
--- backend
location /transactions/authrep.xml {
  content_by_lua_block {
    ngx.exit(200)
  }
}
--- upstream env
location / {
  access_by_lua_block {
      ngx.say("OK")
  }
}
--- request
GET /?user_key=123
--- response_headers
RateLimit-Limit:
RateLimit-Remaining:
RateLimit-Reset: 
--- response_body env
OK
--- error_code: 200
--- no_error_log
[error]


