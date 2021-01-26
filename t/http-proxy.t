use lib 't';
use Test::APIcast::Blackbox 'no_plan';

require("http_proxy.pl");

sub large_body {
  my $res = "";
  for (my $i=0; $i <= 1024; $i++) {
    $res = $res . "1111111 1111111 1111111 1111111\n";
  }
  return $res;
}

$ENV{'LARGE_BODY'} = large_body();

repeat_each(3);

run_tests();

__DATA__


=== TEST 1: APIcast works when NO_PROXY is set
It connects to backened and forwards request to the upstream.
--- env eval
(
  'no_proxy' => '127.0.0.1,localhost',
)
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
     echo 'yay, api backend: $http_host';
  }
--- request
GET /?user_key=value
--- response_body env
yay, api backend: test:$TEST_NGINX_SERVER_PORT
--- error_code: 200
--- no_error_log



=== TEST 2: Downloading configuration uses http proxy + TLS
--- env eval
(
  "http_proxy" => $ENV{TEST_NGINX_HTTP_PROXY},
  'APICAST_CONFIGURATION' => "http://test:$ENV{TEST_NGINX_SERVER_PORT}",
  'APICAST_CONFIGURATION_LOADER' => 'lazy',
  'THREESCALE_DEPLOYMENT_ENV' => 'production',
)
--- upstream env
location = /admin/api/services.json {
  content_by_lua_block {
    ngx.say([[{ "services": [ { "service": { "id": 1337 } } ] }]])
  }
}

location = /admin/api/services/1337/proxy/configs/production/latest.json {
  content_by_lua_block {
    ngx.say([[ { "proxy_config": { "content": { } } }]])
  }
}
--- test

content_by_lua_block {
  local configuration = require('apicast.configuration_loader').load()
  ngx.log(ngx.DEBUG, 'using test block: ', require('cjson').encode(configuration))
}

--- error_code: 200
--- error_log env
proxy request: GET http://127.0.0.1:$TEST_NGINX_SERVER_PORT/admin/api/services.json HTTP/1.1
proxy request: GET http://127.0.0.1:$TEST_NGINX_SERVER_PORT/admin/api/services/1337/proxy/configs/production/latest.json HTTP/1.1
--- no_error_log
[error]



=== TEST 3: Downloading configuration uses http proxy + TLS
--- env random_port eval
(
  "https_proxy" => $ENV{TEST_NGINX_HTTPS_PROXY},
  'APICAST_CONFIGURATION' => "https://test:$ENV{TEST_NGINX_RANDOM_PORT}",
  'APICAST_CONFIGURATION_LOADER' => 'lazy',
  'THREESCALE_DEPLOYMENT_ENV' => 'production',
)
--- upstream env
listen $TEST_NGINX_RANDOM_PORT ssl;

ssl_certificate $TEST_NGINX_SERVER_ROOT/html/server.crt;
ssl_certificate_key $TEST_NGINX_SERVER_ROOT/html/server.key;

location = /admin/api/services.json {
  content_by_lua_block {
    ngx.say([[{ "services": [ { "service": { "id": 1337 } } ] }]])
  }
}

location = /admin/api/services/1337/proxy/configs/production/latest.json {
  content_by_lua_block {
    ngx.say([[ { "proxy_config": { "content": { } } }]])
  }
}
--- user_files fixture=tls.pl eval
--- test
content_by_lua_block {
  local configuration = require('apicast.configuration_loader').load()
  ngx.log(ngx.DEBUG, 'using test block: ', require('cjson').encode(configuration))
}
--- error_code: 200
--- error_log env
proxy request: CONNECT 127.0.0.1:$TEST_NGINX_RANDOM_PORT
--- no_error_log
[error]

=== TEST 4: 3scale backend connection uses proxy
--- env eval
("http_proxy" => $ENV{TEST_NGINX_HTTP_PROXY})
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
     echo 'yay, api backend: $http_host';
  }
--- request
GET /?user_key=value
--- response_body_like
yay, api backend: test:.*
--- error_code: 200
--- error_log env
proxy request: GET http://127.0.0.1:$TEST_NGINX_SERVER_PORT/transactions/authrep.xml?service_token=token-value&service_id=42&usage%5Bhits%5D=2&user_key=value HTTP/1.1
--- no_error_log
[error]



=== TEST 5: 3scale backend connection uses proxy for HTTPS
--- env random_port eval
(
  'https_proxy' => $ENV{TEST_NGINX_HTTPS_PROXY},
  'BACKEND_ENDPOINT_OVERRIDE' => "https://test_backend:$ENV{TEST_NGINX_RANDOM_PORT}"
)
--- configuration env
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
        ]
      }
    }
  ]
}
--- backend env
listen $TEST_NGINX_RANDOM_PORT ssl;

ssl_certificate $TEST_NGINX_SERVER_ROOT/html/server.crt;
ssl_certificate_key $TEST_NGINX_SERVER_ROOT/html/server.key;

location /transactions/authrep.xml {
  access_by_lua_block {
    assert = require('luassert')
    assert.equal('https', ngx.var.scheme)
    assert.equal('$TEST_NGINX_RANDOM_PORT', ngx.var.server_port)
    assert.equal('test_backend', ngx.var.ssl_server_name)
  }

  content_by_lua_block {
    local expected = "service_token=token-value&service_id=42&usage%5Bhits%5D=2&user_key=value"
    require('luassert').same(ngx.decode_args(expected), ngx.req.get_uri_args(0))
  }
}
--- upstream
  location / {
     echo 'yay, api backend: $http_host';
  }
--- request
GET /?user_key=value
--- response_body env
yay, api backend: test:$TEST_NGINX_SERVER_PORT
--- error_code: 200
--- error_log env
proxy request: CONNECT 127.0.0.1:$TEST_NGINX_RANDOM_PORT HTTP/1.1
--- no_error_log
[error]
--- user_files fixture=tls.pl eval



=== TEST 6: 3scale backend connection uses proxy even when using workers
--- env eval
(
  'http_proxy' => $ENV{TEST_NGINX_HTTP_PROXY},
  'APICAST_REPORTING_THREADS' => '1'
)
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
     echo 'yay, api backend: $http_host';
  }
--- test
content_by_lua_block {
  local pending = ngx.timer.pending_count()
  ngx.shared.api_keys:set('42:value:usage%5Bhits%5D=2', 200)

  local res = ngx.location.capture('/apicast?user_key=value')

  while ngx.timer.pending_count() + ngx.timer.running_count() > pending do
    ngx.sleep(0.0001)
  end

  ngx.status = res.status
  ngx.print(res.body)
}

location /apicast {
  internal;
  proxy_set_header Host localhost;
  proxy_pass http://$server_addr:$apicast_port;
}
--- response_body_like
yay, api backend: test:.*
--- error_code: 200
--- error_log env
proxy request: GET http://127.0.0.1:$TEST_NGINX_SERVER_PORT/transactions/authrep.xml?service_token=token-value&service_id=42&usage%5Bhits%5D=2&user_key=value HTTP/1.1
apicast cache write key: 42:value:usage%5Bhits%5D=2, ttl: nil, context: ngx.timer
--- no_error_log
[error]



=== TEST 7: 3scale backend connection uses proxy even when using workers + TLS
--- env random_port eval
(
  'https_proxy' => $ENV{TEST_NGINX_HTTP_PROXY},
  'APICAST_REPORTING_THREADS' => '1',
  'BACKEND_ENDPOINT_OVERRIDE' => "https://test_backend:$ENV{TEST_NGINX_RANDOM_PORT}"
)
--- configuration  env
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
        ]
      }
    }
  ]
}
--- backend env
listen $TEST_NGINX_RANDOM_PORT ssl;

ssl_certificate $TEST_NGINX_SERVER_ROOT/html/server.crt;
ssl_certificate_key $TEST_NGINX_SERVER_ROOT/html/server.key;

location /transactions/authrep.xml {
  access_by_lua_block {
    assert = require('luassert')
    assert.equal('https', ngx.var.scheme)
    assert.equal('$TEST_NGINX_RANDOM_PORT', ngx.var.server_port)
    assert.equal('test_backend', ngx.var.ssl_server_name)
  }

  content_by_lua_block {
    local expected = "service_token=token-value&service_id=42&usage%5Bhits%5D=2&user_key=value"
    require('luassert').same(ngx.decode_args(expected), ngx.req.get_uri_args(0))
  }
}
--- upstream
  location / {
     echo 'yay, api backend: $http_host';
  }
--- test
content_by_lua_block {
  local pending = ngx.timer.pending_count()
  ngx.shared.api_keys:set('42:value:usage%5Bhits%5D=2', 200)

  local res = ngx.location.capture('/apicast?user_key=value')

  while ngx.timer.pending_count() + ngx.timer.running_count() > pending do
    ngx.sleep(0.001)
  end

  ngx.status = res.status
  ngx.print(res.body)
}

location /apicast {
  internal;
  proxy_set_header Host localhost;
  proxy_pass http://$server_addr:$apicast_port;
}
--- response_body env
yay, api backend: test:$TEST_NGINX_SERVER_PORT
--- error_code: 200
--- error_log env
proxy request: CONNECT 127.0.0.1:$TEST_NGINX_RANDOM_PORT
apicast cache write key: 42:value:usage%5Bhits%5D=2, ttl: nil, context: ngx.timer
--- no_error_log
[error]
--- user_files fixture=tls.pl eval



=== TEST 8: upstream API connection uses proxy
--- env eval
("http_proxy" => $ENV{TEST_NGINX_HTTP_PROXY})
--- configuration
{
  "services": [
    {
      "backend_version":  1,
      "proxy": {
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT",
        "proxy_rules": [
          { "pattern": "/test", "http_method": "GET", "metric_system_name": "hits", "delta": 2 }
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
--- upstream
  location /test {
     echo 'yay, api backend: $http_host, uri: $uri, is_args: $is_args, args: $args';
     # echo 'yay, api backend: $http_host, uri:';
  }
--- request
GET /test?user_key=value

--- response_body_like eval
qw/yay, api backend: test:ooo\d+, uri: \/test, is_args: \?, args: user_key=value/
--- error_code: 200
--- error_log env
proxy request: GET http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test?user_key=value HTTP/1.1
--- no_error_log
[error]



=== TEST 9: upstream API connection uses proxy for https
--- env eval
("https_proxy" => $ENV{TEST_NGINX_HTTPS_PROXY})
--- configuration random_port env
{
  "services": [
    {
      "backend_version":  1,
      "proxy": {
        "api_backend": "https://test:$TEST_NGINX_RANDOM_PORT",
        "proxy_rules": [
          { "pattern": "/test", "http_method": "GET", "metric_system_name": "hits", "delta": 2 }
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
--- no_error_log
[error]
--- user_files fixture=tls.pl eval

=== TEST 10: Upstream API with HTTPS POST request, HTTPS_PROXY and HTTPS api_backend
--- env eval
("https_proxy" => $ENV{TEST_NGINX_HTTPS_PROXY})
--- configuration random_port env
{
  "services": [
    {
      "backend_version":  1,
      "proxy": {
        "api_backend": "https://test:$TEST_NGINX_RANDOM_PORT",
        "proxy_rules": [
          { "pattern": "/test", "http_method": "POST", "metric_system_name": "hits", "delta": 2 }
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
    echo_read_request_body;
    echo $request_body;
}
--- request
POST https://localhost/test?user_key=test3
{ "some_param": "some_value" }
--- response_body
{ "some_param": "some_value" }
--- error_code: 200
--- error_log env
proxy request: CONNECT 127.0.0.1:$TEST_NGINX_RANDOM_PORT HTTP/1.1
--- no_error_log
[error]
--- user_files fixture=tls.pl eval

=== TEST 11: Upstream Policy connection uses proxy
--- env eval
("http_proxy" => $ENV{TEST_NGINX_HTTP_PROXY})
--- configuration
{
  "services": [
    {
      "proxy": {
        "policy_chain": [
          { "name": "apicast.policy.upstream",
            "configuration":
              {
                "rules": [ { "regex": "/test", "url": "http://test" } ]
              }
          }
        ]
      }
    }
  ]
}
--- upstream
  location /test {
    echo_foreach_split '\r\n' $echo_client_request_headers;
    echo $echo_it;
    echo_end;
  }
--- request
GET /test?user_key=test3
--- more_headers
User-Agent: Test::APIcast::Blackbox
ETag: foobar
--- response_body
GET /test?user_key=test3 HTTP/1.1
X-Real-IP: 127.0.0.1
Host: test
User-Agent: Test::APIcast::Blackbox
ETag: foobar
--- error_code: 200
--- error_log env
proxy request: GET http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test?user_key=test3 HTTP/1.1
--- no_error_log
[error]



=== TEST 12: Upstream Policy connection uses proxy for https
--- env eval
("https_proxy" => $ENV{TEST_NGINX_HTTPS_PROXY})
--- configuration random_port env
{
  "services": [
    {
      "proxy": {
        "policy_chain": [
          { "name": "apicast.policy.upstream",
            "configuration":
              {
                "rules": [ { "regex": "/test", "url": "https://test:$TEST_NGINX_RANDOM_PORT" } ]
              }
          }
        ]
      }
    }
  ]
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
--- no_error_log
[error]
--- user_files fixture=tls.pl eval


=== TEST 13: Upstream Policy connection uses proxy
--- env eval
("http_proxy" => $ENV{TEST_NGINX_HTTP_PROXY})
--- configuration
{
  "services": [
    {
      "proxy": {
        "policy_chain": [
          { "name": "apicast.policy.upstream",
            "configuration":
              {
                "rules": [ { "regex": "/test", "url": "http://test" } ]
              }
          }
        ]
      }
    }
  ]
}
--- upstream
  location /test {
    echo_foreach_split '\r\n' $echo_client_request_headers;
    echo $echo_it;
    echo_end;
    echo '';
    echo_read_request_body;
    echo $request_body;
  }
--- request
POST /test?user_key=test3
this-is-some-request-body
--- more_headers
User-Agent: Test::APIcast::Blackbox
--- response_body
POST /test?user_key=test3 HTTP/1.1
X-Real-IP: 127.0.0.1
Host: test
Content-Length: 25
User-Agent: Test::APIcast::Blackbox

this-is-some-request-body
--- error_code: 200
--- error_log env
proxy request: POST http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test?user_key=test3 HTTP/1.1
--- no_error_log
[error]


=== TEST 14: Upstream Policy connection uses proxy for https and forwards request body
--- env eval
("https_proxy" => $ENV{TEST_NGINX_HTTPS_PROXY})
--- configuration random_port env
{
  "services": [
    {
      "proxy": {
        "policy_chain": [
          { "name": "apicast.policy.upstream",
            "configuration":
              {
                "rules": [ { "regex": "/test", "url": "https://test:$TEST_NGINX_RANDOM_PORT" } ]
              }
          }
        ]
      }
    }
  ]
}
--- upstream env
listen $TEST_NGINX_RANDOM_PORT ssl;

ssl_certificate $TEST_NGINX_SERVER_ROOT/html/server.crt;
ssl_certificate_key $TEST_NGINX_SERVER_ROOT/html/server.key;

location /test {
    echo_foreach_split '\r\n' $echo_client_request_headers;
    echo $echo_it;
    echo_end;
    echo '';
    echo_read_request_body;
    echo $request_body;

    access_by_lua_block {
       assert = require('luassert')
       assert.equal('https', ngx.var.scheme)
       assert.equal('$TEST_NGINX_RANDOM_PORT', ngx.var.server_port)
       assert.equal('test', ngx.var.ssl_server_name)
    }
}
--- request
POST /test?user_key=test3
this-is-some-request-body
--- more_headers
User-Agent: Test::APIcast::Blackbox
--- response_body env
POST /test?user_key=test3 HTTP/1.1
User-Agent: Test::APIcast::Blackbox
Content-Length: 25
Connection: close
Host: test:$TEST_NGINX_RANDOM_PORT

this-is-some-request-body
--- error_code: 200
--- error_log env
proxy request: CONNECT 127.0.0.1:$TEST_NGINX_RANDOM_PORT HTTP/1.1
--- no_error_log
[error]
--- user_files fixture=tls.pl eval


=== TEST 15: upstream API connection uses proxy and correctly routes to a path.
--- env eval
("http_proxy" => $ENV{TEST_NGINX_HTTP_PROXY})
--- configuration
{
  "services": [
    {
      "backend_version":  1,
      "proxy": {
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/foo",
        "proxy_rules": [
          { "pattern": "/test", "http_method": "GET", "metric_system_name": "hits", "delta": 2 }
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
--- upstream
  location / {
     echo $request;
  }
--- request
GET /test?user_key=value
--- response_body
GET /foo/test?user_key=value HTTP/1.1
--- error_code: 200
--- error_log env
proxy request: GET http://127.0.0.1:$TEST_NGINX_SERVER_PORT/foo/test?user_key=value HTTP/1.1
--- no_error_log
[error]


=== TEST 16: Upstream Policy connection uses proxy and correctly routes to a path.
--- env eval
("http_proxy" => $ENV{TEST_NGINX_HTTP_PROXY})
--- configuration
{
  "services": [
    {
      "proxy": {
        "policy_chain": [
          { "name": "apicast.policy.upstream",
            "configuration":
              {
                "rules": [ { "regex": "/test", "url": "http://test/foo" } ]
              }
          }
        ]
      }
    }
  ]
}
--- upstream
  location / {
    echo $request;
  }
--- request
GET /test?user_key=value
--- response_body
GET /foo/test?user_key=value HTTP/1.1
--- error_code: 200
--- error_log env
proxy request: GET http://127.0.0.1:$TEST_NGINX_SERVER_PORT/foo/test?user_key=value HTTP/1.1
--- no_error_log
[error]

=== TEST 17: Upstream policy with HTTPS POST request, HTTPS_PROXY and HTTPS backend
--- env eval
("https_proxy" => $ENV{TEST_NGINX_HTTPS_PROXY})
--- configuration random_port env
{
  "services": [
    {
      "backend_version":  1,
      "proxy": {
        "api_backend": "https://test:$TEST_NGINX_RANDOM_PORT",
        "proxy_rules": [
          { "pattern": "/test", "http_method": "POST", "metric_system_name": "hits", "delta": 2 }
        ],
        "policy_chain": [
          { "name": "apicast.policy.upstream",
            "configuration":
              {
                "rules": [ { "regex": "/test", "url": "https://test:$TEST_NGINX_RANDOM_PORT" } ]
              }
          },
          {
            "name": "apicast.policy.apicast"
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
    echo_read_request_body;
    echo $request_body;
}
--- request
POST https://localhost/test?user_key=test3
{ "some_param": "some_value" }
--- response_body
{ "some_param": "some_value" }
--- error_code: 200
--- error_log env
proxy request: CONNECT 127.0.0.1:$TEST_NGINX_RANDOM_PORT HTTP/1.1
--- no_error_log
[error]
--- user_files fixture=tls.pl eval

=== TEST 18: The path is set correctly when there are no args and proxied to an http upstream
--- env eval
("http_proxy" => $ENV{TEST_NGINX_HTTP_PROXY})
--- configuration
{
  "services": [
    {
      "proxy": {
        "policy_chain": [
          { "name": "apicast.policy.upstream",
            "configuration":
              {
                "rules": [ { "regex": "/test", "url": "http://test" } ]
              }
          }
        ]
      }
    }
  ]
}
--- upstream
  location /test {
    echo_foreach_split '\r\n' $echo_client_request_headers;
    echo $echo_it;
    echo_end;
  }
--- request
GET /test
--- response_body
GET /test HTTP/1.1
X-Real-IP: 127.0.0.1
Host: test
--- error_code: 200
--- error_log env
proxy request: GET http://127.0.0.1:$TEST_NGINX_SERVER_PORT/test HTTP/1.1
--- no_error_log
[error]

=== TEST 19: The path is set correctly when there are no args and proxied to an https upstream
Regression test: the string 'nil' was appended to the path
--- env eval
("https_proxy" => $ENV{TEST_NGINX_HTTPS_PROXY})
--- configuration random_port env
{
  "services": [
    {
      "proxy": {
        "policy_chain": [
          { "name": "apicast.policy.upstream",
            "configuration":
              {
                "rules": [ { "regex": "/test", "url": "https://test:$TEST_NGINX_RANDOM_PORT" } ]
              }
          }
        ]
      }
    }
  ]
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
GET /test
--- more_headers
User-Agent: Test::APIcast::Blackbox
ETag: foobar
--- response_body env
GET /test HTTP/1.1
User-Agent: Test::APIcast::Blackbox
ETag: foobar
Connection: close
Host: test:$TEST_NGINX_RANDOM_PORT
--- error_code: 200
--- error_log env
proxy request: CONNECT 127.0.0.1:$TEST_NGINX_RANDOM_PORT HTTP/1.1
--- no_error_log
[error]
--- user_files fixture=tls.pl eval


=== TEST 20: Body is larger than client_body_buffer
--- env eval
("https_proxy" => $ENV{TEST_NGINX_HTTPS_PROXY})
--- configuration random_port env
{
  "services": [
    {
      "proxy": {
        "policy_chain": [
          { "name": "apicast.policy.upstream",
            "configuration":
              {
                "rules": [ { "regex": "/test", "url": "https://test:$TEST_NGINX_RANDOM_PORT" } ]
              }
          }
        ]
      }
    }
  ]
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

      ngx.req.read_body()
      local handle = io.open(ngx.req.get_body_file(), "r")
      local body = handle:read("*a")
      assert.equal(#body, 32799)
    }
}
--- request eval
"POST /test \n" . $ENV{LARGE_BODY}
--- error_code: 200
--- error_log env
proxy request: CONNECT 127.0.0.1:$TEST_NGINX_RANDOM_PORT HTTP/1.1
Request body is bigger than client_body_buffer_size
--- no_error_log
[error]
--- user_files fixture=tls.pl eval
