use lib 't';
use Test::APIcast::Blackbox 'no_plan';

env_to_apicast(
    'APICAST_HTTPS_PORT' => "$Test::Nginx::Util::ServerPortForClient",
    'APICAST_HTTPS_CERTIFICATE' => "$Test::Nginx::Util::ServRoot/html/server.crt",
    'APICAST_HTTPS_CERTIFICATE_KEY' => "$Test::Nginx::Util::ServRoot/html/server.key",
    'APICAST_HTTPS_SESSION_REUSE' => 'on',
);

run_tests();

__DATA__
=== TEST 1: Digest of TLS Client Certificate equals to cnf claim
--- backend
  location /transactions/oauth_authrep.xml {
    content_by_lua_block {
      ngx.log(ngx.ERR, 'koko')
      ngx.exit(200)
    }
  }
--- configuration
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
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/",
        "proxy_rules": [
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 1 }
        ],
        "policy_chain": [
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
proxy_set_header Authorization "Bearer eyJraWQiOiJzb21la2lkIiwiYWxnIjoiUlMyNTYifQ.eyJleHAiOjE5MjI2NTMwMTYsInN1YiI6InNvbWVvbmUiLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsiZGlyZWN0b3IiXX0sImZvbyI6IjEiLCJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tL2F1dGgvcmVhbG1zL2FwaWNhc3QiLCJhdWQiOiJhdWRpZW5jZSIsImNuZiI6eyJ4NXQjUzI1NiI6Ilk0L0xWbGtwRTZxa3NjUGJ0b0ttM2lpS0JnZndiT2ZiZEtCRWRuWjZaUFkifX0.YMkzr0eLFjwtJUeCgrbP0rL23GI6hlZvbtEK9e-AP_lc2yFG5TDoACXlqX2ObiygxitxW5egtFZ5Ny3RmokuRw";
log_by_lua_block { collectgarbage() }
--- response_body
GET /t HTTP/1.0
--- error_code: 200
--- no_error_log
[error]
--- user_files fixture=CA/files.pl eval
