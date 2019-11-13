use lib 't';
use Test::APIcast::Blackbox 'no_plan';

require("t/http_proxy.pl");

repeat_each(3);

run_tests();

__DATA__

=== TEST 1: API backend connection uses proxy
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
     echo 'yay, api backend';
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
     echo 'yay, api backend';
  }
--- request
GET /?user_key=value
--- response_body
yay, api backend
--- error_code: 200
--- error_log env
using proxy: $TEST_NGINX_HTTP_PROXY


=== TEST 3: using HTTPS proxy for backend
--- configuration random_port env
{
  "services": [
    {
      "backend_version":  1,
      "proxy": {
        "api_backend": "https://test:$TEST_NGINX_RANDOM_PORT",
        "proxy_rules": [
          { "pattern": "/test", "http_method": "GET", "metric_system_name": "hits", "delta": 2 }
        ],
        "policy_chain": [
          {
            "name": "apicast.policy.apicast"
          },
          {
            "name": "apicast.policy.http_proxy",
            "configuration": {
                "https_proxy": "$TEST_NGINX_HTTPS_PROXY"
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
      ngx.exit(ngx.OK)
    }
  }
--- upstream env
listen $TEST_NGINX_RANDOM_PORT ssl;

ssl_certificate $TEST_NGINX_SERVER_ROOT/html/server.crt;
ssl_certificate_key $TEST_NGINX_SERVER_ROOT/html/server.key;

location /test {
    echo_foreach_split '\r\n' $echo_client_request_headers;
    echo $echo_it;
    echo_end;

    access_by_lua_block {
       assert = require('luassert')
       assert.equal('https', ngx.var.scheme)
       assert.equal('$TEST_NGINX_RANDOM_PORT', ngx.var.server_port)
       assert.equal('test', ngx.var.ssl_server_name)
    }
}
--- request
GET /test?user_key=test3
--- more_headers
User-Agent: Test::APIcast::Blackbox
ETag: foobar
--- response_body env
GET /test?user_key=test3 HTTP/1.1
User-Agent: Test::APIcast::Blackbox
ETag: foobar
Connection: close
Host: test:$TEST_NGINX_RANDOM_PORT
--- error_code: 200
--- error_log env
proxy request: CONNECT 127.0.0.1:$TEST_NGINX_RANDOM_PORT HTTP/1.1
--- user_files fixture=tls.pl eval
--- error_log env
using proxy: $TEST_NGINX_HTTPS_PROXY
