use lib 't';
use Test::APIcast::Blackbox 'no_plan';

check_accum_error_log();
run_tests();

repeat_each(1);

__DATA__

=== TEST 1: Check If-Match is returning 412
--- configuration
{
  "services": [
    {
      "id": 42,
      "proxy": {
        "policy_chain": [
          {
            "name": "apicast.policy.upstream",
            "configuration":
              {
                "rules": [ { "regex": "/", "url": "http://echo" } ]
              }
          }
        ]
      }
    }
  ]
}
--- request
GET /
--- more_headers
If-Match: anything
--- error_code: 412
--- no_error_log
[error]

=== TEST 2: Check If-Match header is deleted and processed
--- backend
  location /transactions/authrep.xml {
    content_by_lua_block {
      ngx.say("OK")
    }
  }
--- configuration
{
  "services": [
    {
      "id": 42,
      "backend_version":  1,
      "backend_authentication_type": "service_token",
      "backend_authentication_value": "token-value",
      "proxy": {
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/",
        "proxy_rules": [
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 2 }
        ],
        "policy_chain": [
          { "name": "apicast.policy.apicast" },
          { "name": "apicast.policy.nginx_filters",
            "configuration": {
              "headers": [
                {"name": "If-Match", "append": false}
              ]
            }
          }
        ]
      }
    }
  ]
}

--- upstream
  location / {
     content_by_lua_block {
       local assert = require('luassert')
       assert.same(ngx.req.get_headers()["If-Match"], nil)
       assert.same(ngx.req.get_headers()["Test"], "one")
       ngx.say('yay, api backend');
     }
  }
--- request
GET /?user_key=foo
--- more_headers
If-Match: anything
Test: one
--- error_code: 200
--- response_body
yay, api backend
--- no_error_log
[error]

=== TEST 3: Check If-Match header is sent to the upstream API
--- backend
  location /transactions/authrep.xml {
    content_by_lua_block {
      ngx.say("OK")
    }
  }
--- configuration
{
  "services": [
    {
      "id": 42,
      "backend_version":  1,
      "backend_authentication_type": "service_token",
      "backend_authentication_value": "token-value",
      "proxy": {
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/",
        "proxy_rules": [
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 2 }
        ],
        "policy_chain": [
          { "name": "apicast.policy.apicast" },
          { "name": "apicast.policy.nginx_filters",
            "configuration": {
              "headers": [
                {"name": "If-Match", "append": true}
              ]
            }
          }
        ]
      }
    }
  ]
}
--- upstream
  location / {
    rewrite_by_lua_block {
      local assert = require('luassert')
      assert.same(ngx.req.get_headers()["If-Match"], "anything")
      assert.same(ngx.req.get_headers()["Test"], "one")
      ngx.req.clear_header("If-Match")
      ngx.say("yay, api backend")
      ngx.exit(200)
    }
  }
--- request
GET /?user_key=foo
--- more_headers
If-Match: anything
Test: one
--- error_code: 200
--- response_body
yay, api backend
--- no_error_log
[error]

