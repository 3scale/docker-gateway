use lib 't';
use Test::APIcast::Blackbox 'no_plan';

run_tests();

__DATA__

=== TEST 1: Use maintenance mode using default values
Testing 3 things:
1) Check default status code
2) Check default response message
3) Validates upstream doesn't get the request

--- configuration
{
  "services": [
    {
      "id": 42,
      "backend_version":  1,
      "backend_authentication_type": "service_token",
      "backend_authentication_value": "token-value",
      "proxy": {
        "policy_chain": [
          { "name": "apicast.policy.maintenance_mode" },
          { "name": "apicast.policy.apicast" }
        ],
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/",
        "proxy_rules": [
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 2 }
        ]
      }
    }
  ]
}
--- upstream
  location / {
    content_by_lua_block {
      local assert = require('luassert')
      assert.is_true(false)
    }
  }
--- request
GET /
--- response_body 
Service Unavailable - Maintenance
--- error_code: 503
--- no_error_log
[error]


=== TEST 2: Use maintenance mode using custom values
Testing 3 things:
1) Check custom status code
2) Check custom response message
3) Validates upstream doesn't get request

--- configuration
{
  "services": [{
    "id": 42,
    "backend_version": 1,
    "backend_authentication_type": "service_token",
    "backend_authentication_value": "token-value",
    "proxy": {
      "policy_chain": [{
          "name": "apicast.policy.maintenance_mode",
          "configuration": {
            "message": "Be back soon",
            "status": 501
          }
        },
        {
          "name": "apicast.policy.apicast"
        }
      ],
      "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/",
      "proxy_rules": [{
        "pattern": "/",
        "http_method": "GET",
        "metric_system_name": "hits",
        "delta": 2
      }]
    }
  }]
}
--- upstream
  location / {
    content_by_lua_block {
      local assert = require('luassert')
      assert.is_true(false)
    }
  }
--- request
GET /
--- response_body 
Be back soon
--- error_code: 501
--- no_error_log
[error]

=== TEST 3: Maintenance policy works when placed after the APIcast policy
In this test we need to send the app credentials, because APIcast will check
that they are there before the maintenance policy runs.
--- configuration
{
  "services": [
    {
      "id": 42,
      "backend_version":  1,
      "backend_authentication_type": "service_token",
      "backend_authentication_value": "token-value",
      "proxy": {
        "policy_chain": [
          { "name": "apicast.policy.apicast" },
          { "name": "apicast.policy.maintenance_mode" }
        ],
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/",
        "proxy_rules": [
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 2 }
        ]
      }
    }
  ]
}
--- upstream
  location / {
    content_by_lua_block {
      local assert = require('luassert')
      assert.is_true(false)
    }
  }
--- request
GET /?user_key=uk
--- response_body
Service Unavailable - Maintenance
--- error_code: 503
--- no_error_log
[error]
