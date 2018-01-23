use lib 't';
use Test::APIcast::Blackbox 'no_plan';

repeat_each(1);

env_to_apicast(
    'APICAST_POLICY_LOAD_PATH' => "$ENV{PWD}/examples/policies"
);

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
          { "name": "maintenance-mode", "version": "1.0.0" },
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
      assert.is_nil(ngx.req.get_uri_args())
      ngx.say('No response from me');
    }
  }
--- request
GET /?test
--- response_body 
503 Service Unavailable - Maintenance
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
          "name": "maintenance-mode", "version": "1.0.0",
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
      assert.is_nil(ngx.req.get_uri_args())
      ngx.say('No response from me');
    }
  }
--- request
GET /?test
--- response_body 
Be back soon
--- error_code: 501
--- no_error_log
[error]
