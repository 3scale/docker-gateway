use lib 't';
use Test::APIcast::Blackbox 'no_plan';

# Load the config on every request, because errors related with the order of
# policies in the chain only appear when loading the config. If we used a cache,
# the second request would fail because the error would not be there.
env_to_apicast(
    'APICAST_CONFIGURATION_LOADER' => 'lazy',
    'APICAST_CONFIGURATION_CACHE'  => 0
);

run_tests();

__DATA__

=== TEST 1: shows an error when policies are placed in an incorrect order
The default credentials policy should be placed after the apicast policy in the
chain. In this test, we are going to place them in the reverse order and check
that APIcast logs an error.
The request returns a 401 status code (credentials missing) because APIcast
cannot set the default credentials.
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
          {
            "name": "apicast.policy.apicast"
          },
          {
            "name": "apicast.policy.default_credentials",
            "configuration": {
              "auth_type": "user_key",
              "user_key": "uk"
            }
          }
        ],
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/",
        "proxy_rules": [
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 2 }
        ]
      }
    }
  ]
}
--- backend
  location /transactions/authrep.xml {
    content_by_lua_block {
      local expected = "service_token=token-value&service_id=42&usage%5Bhits%5D=2&user_key=uk"
      require('luassert').same(ngx.decode_args(expected), ngx.req.get_uri_args(0))
    }
  }
--- upstream
  location / {
     echo 'yay, api backend';
  }
--- request
GET /
--- error_code: 401
--- error_log
Default credentials policy (version: builtin) should be placed before APIcast (version: builtin)


=== TEST 2: does not show any error when policies are placed in the correct order
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
          {
            "name": "apicast.policy.default_credentials",
            "configuration": {
              "auth_type": "user_key",
              "user_key": "uk"
            }
          },
          {
            "name": "apicast.policy.apicast"
          }
        ],
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/",
        "proxy_rules": [
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 2 }
        ]
      }
    }
  ]
}
--- backend
  location /transactions/authrep.xml {
    content_by_lua_block {
      local expected = "service_token=token-value&service_id=42&usage%5Bhits%5D=2&user_key=uk"
      require('luassert').same(ngx.decode_args(expected), ngx.req.get_uri_args(0))
    }
  }
--- upstream
  location / {
     echo 'yay, api backend';
  }
--- request
GET /
--- error_code: 200
--- no_error_log
should be placed
