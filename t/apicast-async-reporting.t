use lib 't';
use Test::APIcast 'no_plan';

env_to_nginx('APICAST_REPORTING_THREADS=1');

run_tests();

__DATA__

=== TEST 1: api backend gets the request
It asks backend and then forwards the request to the api.
--- http_config
include $TEST_NGINX_UPSTREAM_CONFIG;
lua_shared_dict api_keys 1m;
lua_package_path "$TEST_NGINX_LUA_PATH";
init_by_lua_block {
  ngx.shared.api_keys:set('42:value:usage%5Bhits%5D=2', 200)
  require('apicast.configuration_loader').mock({
    services = {
      {
        id = 42,
        backend_version = 1,
        backend_authentication_type = 'service_token',
        backend_authentication_value = 'token-value',
        proxy = {
          backend = { endpoint = "http://127.0.0.1:$TEST_NGINX_SERVER_PORT" },
          api_backend = "http://127.0.0.1:$TEST_NGINX_SERVER_PORT/api-backend/",
          proxy_rules = {
            { pattern = '/', http_method = 'GET', metric_system_name = 'hits', delta = 2 }
          }
        }
      }
    }
  })
}
--- config
include $TEST_NGINX_APICAST_CONFIG;

location /transactions/authrep.xml {
  content_by_lua_block {
    local expected = "service_token=token-value&service_id=42&usage%5Bhits%5D=2&user_key=value"
    require('luassert').same(ngx.decode_args(expected), ngx.req.get_uri_args(0))
  }
}

location /api-backend/ {
  echo 'yay, api backend: $http_host';
}
--- request
GET /?user_key=value
--- response_body env
yay, api backend: 127.0.0.1:$TEST_NGINX_SERVER_PORT
--- error_code: 200
--- no_error_log
[error]

=== TEST 2: https api backend works
with async background reporting
--- ssl random_port
--- http_config
include $TEST_NGINX_UPSTREAM_CONFIG;
lua_package_path "$TEST_NGINX_LUA_PATH";
init_by_lua_block {
  ngx.shared.api_keys:set('42:foo:usage%5Bhits%5D=1', 200)
  require('apicast.configuration_loader').mock({
    services = {
      {
        id = 42,
        backend_version = 1,
        backend_version = 1,
        backend_authentication_type = 'service_token',
        backend_authentication_value = 'token-value',
        proxy = {
          backend = { endpoint = "https://127.0.0.1:$TEST_NGINX_RANDOM_PORT" },
          api_backend = "http://127.0.0.1:$TEST_NGINX_SERVER_PORT/api/",
          proxy_rules = {
            { pattern = '/', http_method = 'GET', metric_system_name = 'hits', delta = 1 }
          }
        }
      }
    }
  })
}
lua_shared_dict api_keys 1m;
--- config
include $TEST_NGINX_APICAST_CONFIG;
listen $TEST_NGINX_RANDOM_PORT ssl;

ssl_certificate ../html/server.crt;
ssl_certificate_key ../html/server.key;

lua_ssl_trusted_certificate ../html/server.crt;

location /api/ {
  echo "api response";
}

location /transactions/authrep.xml {
  content_by_lua_block {
    local expected = "service_token=token-value&service_id=42&usage%5Bhits%5D=1&user_key=foo"
    require('luassert').same(ngx.decode_args(expected), ngx.req.get_uri_args(0))
    ngx.exit(200)
  }
}
--- user_files
>>> server.crt
-----BEGIN CERTIFICATE-----
MIIBkjCCATmgAwIBAgIJAOSlu+H4y+4uMAkGByqGSM49BAEwFDESMBAGA1UEAxMJ
MTI3LjAuMC4xMB4XDTE3MDMzMDA5MDEyMFoXDTI3MDMyODA5MDEyMFowFDESMBAG
A1UEAxMJMTI3LjAuMC4xMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEBmPcgjjx
OmODfbQGqjkVtbq6qvFC8t0A5FWnL3nRQjI5nB9k7tX7vTx1NzFzq+w3Vf3vX+Fq
sWLyaBIhDSyUHqN1MHMwHQYDVR0OBBYEFAIqtTXT/E0eFC29bQhicIZcM0tlMEQG
A1UdIwQ9MDuAFAIqtTXT/E0eFC29bQhicIZcM0tloRikFjAUMRIwEAYDVQQDEwkx
MjcuMC4wLjGCCQDkpbvh+MvuLjAMBgNVHRMEBTADAQH/MAkGByqGSM49BAEDSAAw
RQIgAWRI+63VAyJyJJFfLGPRNhdasQZXSvICnCm7w6C/RmACIQCjZvsLCah8h2Sa
TyxjtHpkHJAzpVuetPVADc/lNN4l/Q==
-----END CERTIFICATE-----
>>> server.key
-----BEGIN EC PARAMETERS-----
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIHIYTPgt2XlDTuL6Ly1jIqhlhM3lEspTyVldsaAoaC54oAoGCCqGSM49
AwEHoUQDQgAEBmPcgjjxOmODfbQGqjkVtbq6qvFC8t0A5FWnL3nRQjI5nB9k7tX7
vTx1NzFzq+w3Vf3vX+FqsWLyaBIhDSyUHg==
-----END EC PRIVATE KEY-----
--- request
GET /test?user_key=foo
--- no_error_log
[error]
--- response_body
api response
--- error_code: 200
--- wait: 3

=== TEST 3: uses endpoint host as Host header
when connecting to the backend
--- main_config
env RESOLVER=127.0.0.1:$TEST_NGINX_RANDOM_PORT;
--- http_config
include $TEST_NGINX_UPSTREAM_CONFIG;
lua_package_path "$TEST_NGINX_LUA_PATH";
lua_shared_dict api_keys 1m;
init_by_lua_block {
  ngx.shared.api_keys:set('42:val:usage%5Bhits%5D=2', 200)
  require('apicast.configuration_loader').mock({
    services = {
      {
        id = 42,
        backend_version = 1,
        backend_authentication_type = 'service_token',
        backend_authentication_value = 'service-token',
        proxy = {
          api_backend = "http://127.0.0.1:$TEST_NGINX_SERVER_PORT/api/",
          backend = {
            endpoint = 'http://localhost.example.com:$TEST_NGINX_SERVER_PORT'
          },
          proxy_rules = {
            { pattern = '/', http_method = 'GET', metric_system_name = 'hits', delta = 2 }
          }
        }
      },
    }
  })
}
--- config
include $TEST_NGINX_APICAST_CONFIG;

location /api/ {
  echo "all ok";
}

location /transactions/authrep.xml {
  content_by_lua_block {
    if ngx.var.host == 'localhost.example.com' then
      ngx.exit(200)
    else
      ngx.log(ngx.ERR, 'invalid host: ', ngx.var.host)
      ngx.exit(404)
    end
  }
}

--- request
GET /t?user_key=val
--- response_body
all ok
--- error_code: 200
--- udp_listen random_port env chomp
$TEST_NGINX_RANDOM_PORT
--- udp_reply dns
[ "localhost.example.com", "127.0.0.1", 60 ]
--- no_error_log
[error]
--- error_log env eval
[
  qr/backend client uri\: http\:\/\/localhost\.example\.com\:$TEST_NGINX_SERVER_PORT\/transactions\/authrep.xml\?.*?(service_id=42).*? ok\: true status\: 200/,
  qr/backend client uri\: http\:\/\/localhost\.example\.com\:$TEST_NGINX_SERVER_PORT\/transactions\/authrep.xml\?.*?(service_token=service\-token).*? ok\: true status\: 200/,
  qr/backend client uri\: http\:\/\/localhost\.example\.com\:$TEST_NGINX_SERVER_PORT\/transactions\/authrep.xml\?.*?(user_key=val).*? ok\: true status\: 200/,
  qr/backend client uri\: http\:\/\/localhost\.example\.com\:$TEST_NGINX_SERVER_PORT\/transactions\/authrep.xml\?.*?(usage%5Bhits%5D=2).*? ok\: true status\: 200/
]
--- wait: 3
