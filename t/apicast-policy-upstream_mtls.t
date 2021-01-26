use lib 't';
use Test::APIcast::Blackbox 'no_plan';

repeat_each(1);
run_tests();


__DATA__

=== TEST 1: MTLS policy with correct certificate
--- init eval
$Test::Nginx::Util::ENDPOINT_SSL_PORT = Test::APIcast::get_random_port();
--- user_files fixture=mutual_ssl.pl eval
--- backend
  location /transactions/authrep.xml {
    content_by_lua_block {
      local expected = "service_token=token-value&service_id=42&usage%5Bhits%5D=2&user_key=value"
      require('luassert').same(ngx.decode_args(expected), ngx.req.get_uri_args(0))
    }
  }
--- configuration eval
<<EOF
{
  "services": [
    {
      "id": 42,
      "backend_version":  1,
      "backend_authentication_type": "service_token",
      "backend_authentication_value": "token-value",
      "proxy": {
        "api_backend": "https://test:$Test::Nginx::Util::ENDPOINT_SSL_PORT/",
        "proxy_rules": [
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 2 }
        ],
        "policy_chain": [
          { "name": "apicast.policy.apicast" },
          {
            "name": "apicast.policy.upstream_mtls",
            "configuration": {
                "certificate": "$ENV{TEST_NGINX_SERVER_ROOT}/html/client.crt",
                "certificate_type": "path",
                "certificate_key": "$ENV{TEST_NGINX_SERVER_ROOT}/html/client.key",
                "certificate_key_type": "path"
            }
          }
        ]
      }
    }
  ]
}
EOF
--- upstream eval
<<EOF
  listen $Test::Nginx::Util::ENDPOINT_SSL_PORT ssl;

  ssl_certificate $ENV{TEST_NGINX_SERVER_ROOT}/html/server.crt;
  ssl_certificate_key $ENV{TEST_NGINX_SERVER_ROOT}/html/server.key;

  ssl_client_certificate $ENV{TEST_NGINX_SERVER_ROOT}/html/client.crt;
  ssl_verify_client on;

  location / {
     echo 'ssl_client_s_dn: \$ssl_client_s_dn';
     echo 'ssl_client_i_dn: \$ssl_client_i_dn';
  }
EOF
--- request
GET /?user_key=value
--- response_body
ssl_client_s_dn: CN=localhost,OU=APIcast,O=3scale
ssl_client_i_dn: CN=localhost,OU=APIcast,O=3scale
--- error_code: 200
--- no_error_log
[error]


=== TEST 2: MTLS policy takes precedence over env variables
In this test we set the env variables to an invalid keys, to make sure that the
correct ones are used.
--- init eval
$Test::Nginx::Util::ENDPOINT_SSL_PORT = Test::APIcast::get_random_port();
--- user_files fixture=mutual_ssl.pl eval
--- env random_port eval
(
  'APICAST_PROXY_HTTPS_CERTIFICATE' => "$Test::Nginx::Util::ServRoot/html/server.crt",
  'APICAST_PROXY_HTTPS_CERTIFICATE_KEY' => "$Test::Nginx::Util::ServRoot/html/server.key",
)

--- backend
  location /transactions/authrep.xml {
    content_by_lua_block {
      local expected = "service_token=token-value&service_id=42&usage%5Bhits%5D=2&user_key=value"
      require('luassert').same(ngx.decode_args(expected), ngx.req.get_uri_args(0))
    }
  }
--- configuration eval
<<EOF
{
  "services": [
    {
      "id": 42,
      "backend_version":  1,
      "backend_authentication_type": "service_token",
      "backend_authentication_value": "token-value",
      "proxy": {
        "api_backend": "https://test:$Test::Nginx::Util::ENDPOINT_SSL_PORT/",
        "proxy_rules": [
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 2 }
        ],
        "policy_chain": [
          { "name": "apicast.policy.apicast" },
          {
            "name": "apicast.policy.upstream_mtls",
            "configuration": {
                "certificate": "$ENV{TEST_NGINX_SERVER_ROOT}/html/client.crt",
                "certificate_type": "path",
                "certificate_key": "$ENV{TEST_NGINX_SERVER_ROOT}/html/client.key",
                "certificate_key_type": "path"
            }
          }
        ]
      }
    }
  ]
}
EOF
--- upstream eval
<<EOF
  listen $Test::Nginx::Util::ENDPOINT_SSL_PORT ssl;

  ssl_certificate $ENV{TEST_NGINX_SERVER_ROOT}/html/server.crt;
  ssl_certificate_key $ENV{TEST_NGINX_SERVER_ROOT}/html/server.key;

  ssl_client_certificate $ENV{TEST_NGINX_SERVER_ROOT}/html/client.crt;
  ssl_verify_client on;

  location / {
     echo 'ssl_client_s_dn: \$ssl_client_s_dn';
     echo 'ssl_client_i_dn: \$ssl_client_i_dn';
  }
EOF
--- request
GET /?user_key=value
--- response_body
ssl_client_s_dn: CN=localhost,OU=APIcast,O=3scale
ssl_client_i_dn: CN=localhost,OU=APIcast,O=3scale
--- error_code: 200
--- no_error_log
[error]


=== TEST 3: MTLS  policy only affects a single service.
Just validate that if two services are used, only the service that matches use
the correct certificate.
--- init eval
$Test::Nginx::Util::ENDPOINT_SSL_PORT = Test::APIcast::get_random_port();
$Test::Nginx::Util::ENDPOINT_SSL_PORT_SECOND = Test::APIcast::get_random_port();
--- user_files fixture=mutual_ssl.pl eval
--- backend
  location /transactions/authrep.xml {
    content_by_lua_block {
      return ngx.exit(200)
    }
  }
--- configuration eval
<<EOF
{
  "services": [
    {
      "id": 42,
      "backend_version":  1,
      "backend_authentication_type": "service_token",
      "backend_authentication_value": "token-value",
      "proxy": {
        "hosts": [
          "one"
        ],
        "api_backend": "https://test:$Test::Nginx::Util::ENDPOINT_SSL_PORT/",
        "proxy_rules": [
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 2 }
        ],
        "policy_chain": [
          { "name": "apicast.policy.apicast" },
          {
            "name": "apicast.policy.upstream_mtls",
            "configuration": {
                "certificate": "$ENV{TEST_NGINX_SERVER_ROOT}/html/client.crt",
                "certificate_type": "path",
                "certificate_key": "$ENV{TEST_NGINX_SERVER_ROOT}/html/client.key",
                "certificate_key_type": "path"
            }
          }
        ]
      }
    },
    {
      "id": 24,
      "backend_version":  1,
      "backend_authentication_type": "service_token",
      "backend_authentication_value": "token-value",
      "proxy": {
        "hosts": [
          "two"
        ],
        "api_backend": "https://test:$Test::Nginx::Util::ENDPOINT_SSL_PORT_SECOND/",
        "proxy_rules": [
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 2 }
        ],
        "policy_chain": [
          { "name": "apicast.policy.apicast" },
          {
            "name": "apicast.policy.upstream_mtls",
            "configuration": {
                "certificate": "$ENV{TEST_NGINX_SERVER_ROOT}/html/client.crt",
                "certificate_type": "path",
                "certificate_key": "$ENV{TEST_NGINX_SERVER_ROOT}/html/client.key",
                "certificate_key_type": "path"
            }
          }
        ]
      }
    }
  ]
}
EOF
--- upstream eval
<<EOF
  listen $Test::Nginx::Util::ENDPOINT_SSL_PORT ssl;

  ssl_certificate $ENV{TEST_NGINX_SERVER_ROOT}/html/server.crt;
  ssl_certificate_key $ENV{TEST_NGINX_SERVER_ROOT}/html/server.key;

  ssl_client_certificate $ENV{TEST_NGINX_SERVER_ROOT}/html/client.crt;
  ssl_verify_client on;

  location /test/ {
     echo 'ssl_client_s_dn: \$ssl_client_s_dn';
     echo 'ssl_client_i_dn: \$ssl_client_i_dn';
  }
  }
  # This is a bit hacky to listen in multiple ports
  server {
  listen $Test::Nginx::Util::ENDPOINT_SSL_PORT_SECOND ssl;

  ssl_certificate $ENV{TEST_NGINX_SERVER_ROOT}/html/server.crt;
  ssl_certificate_key $ENV{TEST_NGINX_SERVER_ROOT}/html/server.key;

  location / {
     echo 'yay, API backend';
  }
EOF
--- request eval
["GET /test/?user_key=value", "GET /test/?user_key=value"]
--- more_headers eval
["Host: one", "Host: two"]
--- response_body eval
[
  "ssl_client_s_dn: CN=localhost,OU=APIcast,O=3scale\nssl_client_i_dn: CN=localhost,OU=APIcast,O=3scale\n",
  "yay, API backend\n"
]
--- error_code eval
[200, 200]
--- no_error_log
[error]
