use lib 't';
use Test::APIcast::Blackbox 'no_plan';

require("http_proxy.pl");

repeat_each(1);

run_tests();

__DATA__

=== TEST 1: API backend connection uses http proxy
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
          {
            "name": "apicast.policy.apicast"
          },
          {
            "name": "apicast.policy.camel",
            "configuration": {
                "http_proxy": "$TEST_NGINX_HTTP_PROXY"
            }
          }
        ]
      }
    }
  ]
}
--- backend
  location /transactions/authrep.xml {
    content_by_lua_block {
      local expected = "service_token=token-value&service_id=42&usage%5Bhits%5D=2&user_key=value"
      require('luassert').same(ngx.decode_args(expected), ngx.req.get_uri_args(0))
    }
  }
--- upstream
  location / {
    access_by_lua_block {
      local host = ngx.req.get_headers()["Host"]
      local result = string.match(host, "^test:")
      local assert = require('luassert')
      assert.equals(result, "test:")
      ngx.say("yay, api backend")
    }
  }
--- request
GET /?user_key=value
--- response_body
yay, api backend
--- error_code: 200
--- error_log env
using proxy: $TEST_NGINX_HTTP_PROXY

=== TEST 2: API backend using all_proxy
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
          {
            "name": "apicast.policy.apicast"
          },
          {
            "name": "apicast.policy.http_proxy",
            "configuration": {
                "all_proxy": "$TEST_NGINX_HTTP_PROXY"
            }
          }
        ]
      }
    }
  ]
}
--- backend
  location /transactions/authrep.xml {
    content_by_lua_block {
      local expected = "service_token=token-value&service_id=42&usage%5Bhits%5D=2&user_key=value"
      require('luassert').same(ngx.decode_args(expected), ngx.req.get_uri_args(0))
    }
  }
--- upstream
  location / {
    access_by_lua_block {
      local host = ngx.req.get_headers()["Host"]
      local result = string.match(host, "^test:")
      local assert = require('luassert')
      assert.equals(result, "test:")
      ngx.say("yay, api backend")
    }
  }
--- request
GET /?user_key=value
--- response_body
yay, api backend
--- error_code: 200
--- error_log env
using proxy: $TEST_NGINX_HTTP_PROXY


=== TEST 3: using HTTPS proxy for backend
--- init eval
$Test::Nginx::Util::PROXY_SSL_PORT = Test::APIcast::get_random_port();
$Test::Nginx::Util::ENDPOINT_SSL_PORT = Test::APIcast::get_random_port();
--- configuration random_port env eval
<<EOF
{
  "services": [
    {
      "backend_version":  1,
      "proxy": {
        "api_backend": "https://localhost:$Test::Nginx::Util::ENDPOINT_SSL_PORT",
        "proxy_rules": [
          { "pattern": "/test", "http_method": "GET", "metric_system_name": "hits", "delta": 2 }
        ],
        "policy_chain": [
          {
            "name": "apicast.policy.apicast"
          },
          {
            "name": "apicast.policy.camel",
            "configuration": {
                "https_proxy": "http://127.0.0.1:$Test::Nginx::Util::PROXY_SSL_PORT"
            }
          }
        ]
      }
    }
  ]
}
EOF
--- backend
  location /transactions/authrep.xml {
    content_by_lua_block {
      ngx.exit(ngx.OK)
    }
  }
--- upstream eval
<<EOF
  # Endpoint config
  listen $Test::Nginx::Util::ENDPOINT_SSL_PORT ssl;

  ssl_certificate $Test::Nginx::Util::ServRoot/html/server.crt;
  ssl_certificate_key $Test::Nginx::Util::ServRoot/html/server.key;

  server_name _ default_server;

  location /test {
    access_by_lua_block {
      assert = require('luassert')
      assert.equal('https', ngx.var.scheme)
      assert.equal('$Test::Nginx::Util::ENDPOINT_SSL_PORT', ngx.var.server_port)
      assert.equal('localhost', ngx.var.ssl_server_name)
      assert.equal(ngx.var.request_uri, '/test?user_key=test3')

      local host = ngx.req.get_headers()["Host"]
      assert.equal(host, 'localhost:$Test::Nginx::Util::ENDPOINT_SSL_PORT')
      ngx.say("yay, endpoint backend")

    }
  }
}
server {
  # Proxy config
  listen $Test::Nginx::Util::PROXY_SSL_PORT ssl;

  ssl_certificate $Test::Nginx::Util::ServRoot/html/server.crt;
  ssl_certificate_key $Test::Nginx::Util::ServRoot/html/server.key;


  server_name _ default_server;

  location ~ /.* {
    proxy_http_version 1.1;
    proxy_pass https://\$http_host;
  }
EOF
--- request
GET /test?user_key=test3
--- more_headers
User-Agent: Test::APIcast::Blackbox
ETag: foobar
--- error_code: 200
--- user_files fixture=tls.pl eval
--- error_log eval
<<EOF
using proxy: http://127.0.0.1:$Test::Nginx::Util::PROXY_SSL_PORT,
EOF



=== TEST 4: using HTTPS proxy without api_backend upstream
--- init eval
$Test::Nginx::Util::PROXY_SSL_PORT = Test::APIcast::get_random_port();
$Test::Nginx::Util::ENDPOINT_SSL_PORT = Test::APIcast::get_random_port();
--- configuration random_port env eval
<<EOF
{
  "services": [
    {
      "backend_version":  1,
      "proxy": {
        "proxy_rules": [
          { "pattern": "/test", "http_method": "GET", "metric_system_name": "hits", "delta": 2 }
        ],
        "policy_chain": [
          {
            "name": "apicast.policy.routing",
            "configuration": {
              "rules": [
                {
                  "url": "https://localhost:$Test::Nginx::Util::ENDPOINT_SSL_PORT",
                  "condition": {
                    "operations": [
                      {
                        "match": "liquid",
                        "liquid_value": "test",
                        "op": "==",
                        "value": "test"
                      }
                    ]
                  }
                }
              ]
            }
          },
          {
            "name": "apicast.policy.apicast"
          },
          {
            "name": "apicast.policy.camel",
            "configuration": {
                "https_proxy": "http://127.0.0.1:$Test::Nginx::Util::PROXY_SSL_PORT"
            }
          }
        ]
      }
    }
  ]
}
EOF
--- backend
  location /transactions/authrep.xml {
    content_by_lua_block {
      ngx.exit(ngx.OK)
    }
  }
--- upstream eval
<<EOF
  # Endpoint config
  listen $Test::Nginx::Util::ENDPOINT_SSL_PORT ssl;

  ssl_certificate $Test::Nginx::Util::ServRoot/html/server.crt;
  ssl_certificate_key $Test::Nginx::Util::ServRoot/html/server.key;

  server_name _ default_server;

  location /test {
    access_by_lua_block {
      assert = require('luassert')
      assert.equal('https', ngx.var.scheme)
      assert.equal('$Test::Nginx::Util::ENDPOINT_SSL_PORT', ngx.var.server_port)
      assert.equal('localhost', ngx.var.ssl_server_name)
      assert.equal(ngx.var.request_uri, '/test?user_key=test3')

      local host = ngx.req.get_headers()["Host"]
      assert.equal(host, 'localhost:$Test::Nginx::Util::ENDPOINT_SSL_PORT')
      ngx.say("yay, endpoint backend")

    }
  }
}
server {
  # Proxy config
  listen $Test::Nginx::Util::PROXY_SSL_PORT ssl;

  ssl_certificate $Test::Nginx::Util::ServRoot/html/server.crt;
  ssl_certificate_key $Test::Nginx::Util::ServRoot/html/server.key;


  server_name _ default_server;

  location ~ /.* {
    proxy_http_version 1.1;
    proxy_pass https://\$http_host;
  }
EOF
--- request
GET /test?user_key=test3
--- more_headers
User-Agent: Test::APIcast::Blackbox
ETag: foobar
--- error_code: 200
--- user_files fixture=tls.pl eval
--- error_log eval
<<EOF
using proxy: http://127.0.0.1:$Test::Nginx::Util::PROXY_SSL_PORT,
EOF
