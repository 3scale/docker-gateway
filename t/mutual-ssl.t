use lib 't';
use Test::APIcast::Blackbox 'no_plan';

env_to_apicast(
    'APICAST_PROXY_HTTPS_CERTIFICATE' => "$Test::Nginx::Util::ServRoot/html/client.crt",
    'APICAST_PROXY_HTTPS_CERTIFICATE_KEY' => "$Test::Nginx::Util::ServRoot/html/client.key",
    'APICAST_PROXY_HTTPS_PASSWORD_FILE' => "$Test::Nginx::Util::ServRoot/html/passwords.file",
    'APICAST_PROXY_HTTPS_SESSION_REUSE' => 'on',
);

run_tests();

__DATA__

=== TEST 1: Mutual SSL with password file
--- ssl random_port
--- configuration
{
  "services": [
    {
      "id": 42,
      "backend_version":  1,
      "backend_authentication_type": "service_token",
      "backend_authentication_value": "token-value",
      "proxy": {
        "api_backend": "https://test:$TEST_NGINX_RANDOM_PORT/",
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
        ngx.exit(200)
    }
  }
--- upstream env
  listen $TEST_NGINX_RANDOM_PORT ssl;

  ssl_certificate $TEST_NGINX_SERVER_ROOT/html/server.crt;
  ssl_certificate_key $TEST_NGINX_SERVER_ROOT/html/server.key;

  ssl_client_certificate $TEST_NGINX_SERVER_ROOT/html/client.crt;
  ssl_verify_client on;

  location / {
     echo 'ssl_client_s_dn: $ssl_client_s_dn';
     echo 'ssl_client_i_dn: $ssl_client_i_dn';
  }
--- request
GET /?user_key=uk
--- response_body
ssl_client_s_dn: CN=localhost,OU=APIcast,O=3scale
ssl_client_i_dn: CN=localhost,OU=APIcast,O=3scale
--- error_code: 200
--- no_error_log
[error]
--- user_files fixture=mutual_ssl.pl eval
