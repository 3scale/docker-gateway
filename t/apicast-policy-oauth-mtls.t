use lib 't';
use Test::APIcast::Blackbox 'no_plan';

env_to_apicast(
    'APICAST_HTTPS_PORT' => "$Test::Nginx::Util::ServerPortForClient",
    'APICAST_HTTPS_CERTIFICATE' => "$Test::Nginx::Util::ServRoot/html/server.crt",
    'APICAST_HTTPS_CERTIFICATE_KEY' => "$Test::Nginx::Util::ServRoot/html/server.key",
);

run_tests();

__DATA__
=== TEST 1: Digest of TLS Client Certificate equals to cnf claim
--- env eval
(
  'BACKEND_ENDPOINT_OVERRIDE' => '' # disable override by Test::APIcast::Blackbox
)
--- backend random_port env
  listen $TEST_NGINX_RANDOM_PORT;
  location /transactions/oauth_authrep.xml {
    content_by_lua_block {
      ngx.exit(200)
    }
  }

  location /t {
    content_by_lua_block {
      ngx.say('yay, api backend')
      ngx.exit(200)
    }
  }
--- configuration random_port env
{
  "oidc": [
    {
      "issuer": "https://example.com/auth/realms/apicast",
      "config": { "id_token_signing_alg_values_supported": [ "RS256" ] },
      "keys": { "somekid": { "pem": "-----BEGIN PUBLIC KEY-----\nMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALClz96cDQ965ENYMfZzG+Acu25lpx2K\nNpAALBQ+catCA59us7+uLY5rjQR6SOgZpCz5PJiKNAdRPDJMXSmXqM0CAwEAAQ==\n-----END PUBLIC KEY-----" } }
    }
  ],
  "services": [
    {
      "id": 42,
      "backend_version": "oauth",
      "backend_authentication_type": "service_token",
      "backend_authentication_value": "token-value",
      "proxy": {
        "authentication_method": "oidc",
        "oidc_issuer_endpoint": "https://example.com/auth/realms/apicast",
        "api_backend": "http://test_backend:$TEST_NGINX_RANDOM_PORT/",
        "backend": {
          "endpoint": "http://test_backend:$TEST_NGINX_RANDOM_PORT/",
          "host": "localhost"
        },
        "proxy_rules": [
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 1 }
        ],
        "policy_chain": [
          { "name": "apicast.policy.oauth_mtls" },
          { "name": "apicast.policy.apicast" }
        ]
      }
    }
  ]
}
--- test env
proxy_ssl_verify on;
proxy_ssl_trusted_certificate $TEST_NGINX_SERVER_ROOT/html/ca.crt;
proxy_ssl_certificate $TEST_NGINX_SERVER_ROOT/html/client.crt;
proxy_ssl_certificate_key $TEST_NGINX_SERVER_ROOT/html/client.key;
proxy_pass https://$server_addr:$apicast_port/t;
proxy_set_header Host localhost;
proxy_set_header Authorization "Bearer eyJraWQiOiJzb21la2lkIiwiYWxnIjoiUlMyNTYifQ.eyJleHAiOjE5MjY4NzMwNTQsInN1YiI6InNvbWVvbmUiLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsiZGlyZWN0b3IiXX0sImZvbyI6IjEiLCJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tL2F1dGgvcmVhbG1zL2FwaWNhc3QiLCJhdWQiOiJhdWRpZW5jZSIsImNuZiI6eyJ4NXQjUzI1NiI6Ilk0X0xWbGtwRTZxa3NjUGJ0b0ttM2lpS0JnZndiT2ZiZEtCRWRuWjZaUFkifX0.Iin-tr6EVhEXjbj9R6xZSToBxZZBDXhl6i9ROw6SJQE6RWJeLt6mKK4jdTMVdxoZfm1J_NqayGJh3N99kHdIbA";
log_by_lua_block { collectgarbage() }
--- response_body
yay, api backend
--- error_code: 200
--- no_error_log
[error]
--- user_files fixture=CA/files.pl eval

=== TEST 2: Digest of TLS Client Certificate does not equal to cnf claim
--- env eval
(
  'BACKEND_ENDPOINT_OVERRIDE' => '' # disable override by Test::APIcast::Blackbox
)
--- backend random_port env
  listen $TEST_NGINX_RANDOM_PORT;
  location /transactions/oauth_authrep.xml {
    content_by_lua_block {
      ngx.exit(200)
    }
  }

  location /t {
    content_by_lua_block {
      ngx.say('yay, api backend')
      ngx.exit(200)
    }
  }
--- configuration random_port env
{
  "oidc": [
    {
      "issuer": "https://example.com/auth/realms/apicast",
      "config": { "id_token_signing_alg_values_supported": [ "RS256" ] },
      "keys": { "somekid": { "pem": "-----BEGIN PUBLIC KEY-----\nMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALClz96cDQ965ENYMfZzG+Acu25lpx2K\nNpAALBQ+catCA59us7+uLY5rjQR6SOgZpCz5PJiKNAdRPDJMXSmXqM0CAwEAAQ==\n-----END PUBLIC KEY-----" } }
    }
  ],
  "services": [
    {
      "id": 42,
      "backend_version": "oauth",
      "backend_authentication_type": "service_token",
      "backend_authentication_value": "token-value",
      "proxy": {
        "authentication_method": "oidc",
        "oidc_issuer_endpoint": "https://example.com/auth/realms/apicast",
        "api_backend": "http://test_backend:$TEST_NGINX_RANDOM_PORT/",
        "backend": {
          "endpoint": "http://test_backend:$TEST_NGINX_RANDOM_PORT/",
          "host": "localhost"
        },
        "proxy_rules": [
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 1 }
        ],
        "policy_chain": [
          { "name": "apicast.policy.oauth_mtls" },
          { "name": "apicast.policy.apicast" }
        ]
      }
    }
  ]
}
--- test env
proxy_ssl_verify on;
proxy_ssl_trusted_certificate $TEST_NGINX_SERVER_ROOT/html/ca.crt;
proxy_ssl_certificate $TEST_NGINX_SERVER_ROOT/html/client.crt;
proxy_ssl_certificate_key $TEST_NGINX_SERVER_ROOT/html/client.key;
proxy_pass https://$server_addr:$apicast_port/t;
proxy_set_header Host localhost;
proxy_set_header Authorization "Bearer eyJraWQiOiJzb21la2lkIiwiYWxnIjoiUlMyNTYifQ.eyJleHAiOjE5MjQxMjQ1ODIsInN1YiI6InNvbWVvbmUiLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsiZGlyZWN0b3IiXX0sImZvbyI6IjEiLCJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tL2F1dGgvcmVhbG1zL2FwaWNhc3QiLCJhdWQiOiJhdWRpZW5jZSIsImNuZiI6eyJ4NXQjUzI1NiI6ImludmFsaWQifX0.h9Lay5rff08ipXd2juLS_A0fpJKn6UPD1AIxBCibdTi1wyhF5fCLmxzfwozgtqVTlcOGTu9ZtVfp88tRZ2mE-A";
log_by_lua_block { collectgarbage() }
--- response_body chomp
{"error": "invalid_token"}
--- error_code: 401
--- no_error_log
[error]
--- user_files fixture=CA/files.pl eval

=== TEST 3: TLS Client Certificate is not provided
--- env eval
(
  'BACKEND_ENDPOINT_OVERRIDE' => '' # disable override by Test::APIcast::Blackbox
)
--- backend random_port env
  listen $TEST_NGINX_RANDOM_PORT;
  location /transactions/oauth_authrep.xml {
    content_by_lua_block {
      ngx.exit(200)
    }
  }

  location /t {
    content_by_lua_block {
      ngx.say('yay, api backend')
      ngx.exit(200)
    }
  }
--- configuration random_port env
{
  "oidc": [
    {
      "issuer": "https://example.com/auth/realms/apicast",
      "config": { "id_token_signing_alg_values_supported": [ "RS256" ] },
      "keys": { "somekid": { "pem": "-----BEGIN PUBLIC KEY-----\nMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALClz96cDQ965ENYMfZzG+Acu25lpx2K\nNpAALBQ+catCA59us7+uLY5rjQR6SOgZpCz5PJiKNAdRPDJMXSmXqM0CAwEAAQ==\n-----END PUBLIC KEY-----" } }
    }
  ],
  "services": [
    {
      "id": 42,
      "backend_version": "oauth",
      "backend_authentication_type": "service_token",
      "backend_authentication_value": "token-value",
      "proxy": {
        "authentication_method": "oidc",
        "oidc_issuer_endpoint": "https://example.com/auth/realms/apicast",
        "api_backend": "http://test_backend:$TEST_NGINX_RANDOM_PORT/",
        "backend": {
          "endpoint": "http://test_backend:$TEST_NGINX_RANDOM_PORT/",
          "host": "localhost"
        },
        "proxy_rules": [
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 1 }
        ],
        "policy_chain": [
          { "name": "apicast.policy.oauth_mtls" },
          { "name": "apicast.policy.apicast" }
        ]
      }
    }
  ]
}
--- test env
proxy_ssl_verify on;
proxy_ssl_trusted_certificate $TEST_NGINX_SERVER_ROOT/html/ca.crt;
proxy_pass https://$server_addr:$apicast_port/t;
proxy_set_header Host localhost;
proxy_set_header Authorization "Bearer eyJraWQiOiJzb21la2lkIiwiYWxnIjoiUlMyNTYifQ.eyJleHAiOjE5MjY4NzMwNTQsInN1YiI6InNvbWVvbmUiLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsiZGlyZWN0b3IiXX0sImZvbyI6IjEiLCJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tL2F1dGgvcmVhbG1zL2FwaWNhc3QiLCJhdWQiOiJhdWRpZW5jZSIsImNuZiI6eyJ4NXQjUzI1NiI6Ilk0X0xWbGtwRTZxa3NjUGJ0b0ttM2lpS0JnZndiT2ZiZEtCRWRuWjZaUFkifX0.Iin-tr6EVhEXjbj9R6xZSToBxZZBDXhl6i9ROw6SJQE6RWJeLt6mKK4jdTMVdxoZfm1J_NqayGJh3N99kHdIbA";
log_by_lua_block { collectgarbage() }
--- response_body chomp
{"error": "invalid_token"}
--- error_code: 401
--- no_error_log
[error]
--- user_files fixture=CA/files.pl eval

=== TEST 4: cnf claim is not provided
--- env eval
(
  'BACKEND_ENDPOINT_OVERRIDE' => '' # disable override by Test::APIcast::Blackbox
)
--- backend random_port env
  listen $TEST_NGINX_RANDOM_PORT;
  location /transactions/oauth_authrep.xml {
    content_by_lua_block {
      ngx.exit(200)
    }
  }

  location /t {
    content_by_lua_block {
      ngx.say('yay, api backend')
      ngx.exit(200)
    }
  }
--- configuration random_port env
{
  "oidc": [
    {
      "issuer": "https://example.com/auth/realms/apicast",
      "config": { "id_token_signing_alg_values_supported": [ "RS256" ] },
      "keys": { "somekid": { "pem": "-----BEGIN PUBLIC KEY-----\nMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALClz96cDQ965ENYMfZzG+Acu25lpx2K\nNpAALBQ+catCA59us7+uLY5rjQR6SOgZpCz5PJiKNAdRPDJMXSmXqM0CAwEAAQ==\n-----END PUBLIC KEY-----" } }
    }
  ],
  "services": [
    {
      "id": 42,
      "backend_version": "oauth",
      "backend_authentication_type": "service_token",
      "backend_authentication_value": "token-value",
      "proxy": {
        "authentication_method": "oidc",
        "oidc_issuer_endpoint": "https://example.com/auth/realms/apicast",
        "api_backend": "http://test_backend:$TEST_NGINX_RANDOM_PORT/",
        "backend": {
          "endpoint": "http://test_backend:$TEST_NGINX_RANDOM_PORT/",
          "host": "localhost"
        },
        "proxy_rules": [
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 1 }
        ],
        "policy_chain": [
          { "name": "apicast.policy.oauth_mtls" },
          { "name": "apicast.policy.apicast" }
        ]
      }
    }
  ]
}
--- test env
proxy_ssl_verify on;
proxy_ssl_trusted_certificate $TEST_NGINX_SERVER_ROOT/html/ca.crt;
proxy_ssl_certificate $TEST_NGINX_SERVER_ROOT/html/client.crt;
proxy_ssl_certificate_key $TEST_NGINX_SERVER_ROOT/html/client.key;
proxy_pass https://$server_addr:$apicast_port/t;
proxy_set_header Host localhost;
proxy_set_header Authorization "Bearer eyJraWQiOiJzb21la2lkIiwiYWxnIjoiUlMyNTYifQ.eyJleHAiOjE5MjQxMjU0MzQsInN1YiI6InNvbWVvbmUiLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsiZGlyZWN0b3IiXX0sImZvbyI6IjEiLCJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tL2F1dGgvcmVhbG1zL2FwaWNhc3QiLCJhdWQiOiJhdWRpZW5jZSJ9.GDYu4nT73_vPV4ZGa5DL8TAWZvn2TI47WxbXFH6wnUMn818slif-gUp_14pGleOR6VcLrEAC3VwEidtn08Ah8A";
log_by_lua_block { collectgarbage() }
--- response_body chomp
{"error": "invalid_token"}
--- error_code: 401
--- no_error_log
[error]
--- user_files fixture=CA/files.pl eval
