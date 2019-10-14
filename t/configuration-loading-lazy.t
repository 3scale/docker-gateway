use lib 't';
use Test::APIcast 'no_plan';

$ENV{TEST_NGINX_HTTP_CONFIG} = "$Test::APIcast::path/http.d/init.conf";

$ENV{APICAST_CONFIGURATION_LOADER} = 'lazy';

env_to_nginx(
    'APICAST_CONFIGURATION_LOADER',
    'TEST_NGINX_APICAST_PATH',
    'THREESCALE_CONFIG_FILE',
    'THREESCALE_PORTAL_ENDPOINT'
);

run_tests();

__DATA__

=== TEST 1: load empty configuration
should just say service is not found
--- main_config
env THREESCALE_PORTAL_ENDPOINT=http://127.0.0.1:$TEST_NGINX_SERVER_PORT;
--- http_config
  include $TEST_NGINX_HTTP_CONFIG;
  lua_package_path "$TEST_NGINX_LUA_PATH";
--- config
  include $TEST_NGINX_APICAST_CONFIG;

  location = /admin/api/nginx/spec.json {
   echo "{}";
  }
--- request
GET /t
--- error_code: 404
--- error_log
service not found for host localhost

=== TEST 2: load invalid configuration
should fail with server error
--- main_config
env THREESCALE_PORTAL_ENDPOINT=http://127.0.0.1:$TEST_NGINX_SERVER_PORT;
--- http_config
  include $TEST_NGINX_HTTP_CONFIG;
  lua_package_path "$TEST_NGINX_LUA_PATH";
--- config
  include $TEST_NGINX_APICAST_CONFIG;

  location = /admin/api/nginx/spec.json {
    echo "";
  }
--- request
GET /t
--- error_code: 404

=== TEST 3: load valid configuration
should correctly route the request
--- main_config
env THREESCALE_PORTAL_ENDPOINT=http://127.0.0.1:$TEST_NGINX_SERVER_PORT/;
env APICAST_CONFIGURATION_LOADER=lazy;
--- http_config
  include $TEST_NGINX_HTTP_CONFIG;
  include $TEST_NGINX_UPSTREAM_CONFIG;
  lua_package_path "$TEST_NGINX_LUA_PATH";
--- config
  include $TEST_NGINX_APICAST_CONFIG;
  include $TEST_NGINX_BACKEND_CONFIG;

  location = /admin/api/nginx/spec.json {
    try_files /config.json =404;
  }

  location /api/ {
    echo "all ok";
  }
--- request
GET /t?user_key=fake
--- error_code: 200
--- user_files eval
[
  [ 'config.json', qq|
  {
    "services": [{
      "id": 1,
      "backend_version": 1,
      "proxy": {
        "api_backend": "http://127.0.0.1:$Test::Nginx::Util::ServerPortForClient/api/",
        "backend": {
          "endpoint": "http://127.0.0.1:$Test::Nginx::Util::ServerPortForClient"
        },
        "proxy_rules": [
          { "pattern": "/t", "http_method": "GET", "metric_system_name": "test","delta": 1 }
        ]
      }
    }]
  }
  | ]
]

=== TEST 4: load invalid json
To validate that process does not died with invalid config
--- main_config
env THREESCALE_PORTAL_ENDPOINT=http://127.0.0.1:$TEST_NGINX_SERVER_PORT/;
env APICAST_CONFIGURATION_LOADER=lazy;
--- http_config
  include $TEST_NGINX_UPSTREAM_CONFIG;
  lua_package_path "$TEST_NGINX_LUA_PATH";
--- config
  include $TEST_NGINX_APICAST_CONFIG;
  include $TEST_NGINX_BACKEND_CONFIG;

  location = /admin/api/nginx/spec.json {
    try_files /config.json =404;
  }

  location /api/ {
    echo "all ok";
  }
--- request
GET /t?user_key=fake
--- error_code: 404
--- user_files
>>> config.json
{Hello, world}
--- no_error_log
[error]

=== TEST 5: load invalid oidc target url
--- main_config
env THREESCALE_PORTAL_ENDPOINT=http://127.0.0.1:$TEST_NGINX_SERVER_PORT/;
env APICAST_CONFIGURATION_LOADER=lazy;
--- http_config
  include $TEST_NGINX_HTTP_CONFIG;
  include $TEST_NGINX_UPSTREAM_CONFIG;
  lua_package_path "$TEST_NGINX_LUA_PATH";
--- config
  include $TEST_NGINX_APICAST_CONFIG;
  include $TEST_NGINX_BACKEND_CONFIG;

  location = /admin/api/nginx/spec.json {
    try_files /config.json =404;
  }

  location /api/ {
    echo "all ok";
  }
--- request
GET /t?user_key=fake
--- error_code: 401
--- user_files eval
[
  [ 'config.json', qq|
  {
    "services": [{
      "id": 1,
      "backend_version": 1,
      "backend_version": "oauth",
      "proxy": {
        "api_backend": "http://127.0.0.1:$Test::Nginx::Util::ServerPortForClient/api/",
        "service_id": 2555417794444,
        "oidc_issuer_endpoint": "www.fgoodl/adasd",
        "authentication_method": "oidc",
        "service_backend_version": "oauth",
        "hosts": [
          "localhost"
        ],
        "backend": {
          "endpoint": "http://127.0.0.1:$Test::Nginx::Util::ServerPortForClient"
        },
        "proxy_rules": [
          { "pattern": "/t", "http_method": "GET", "metric_system_name": "test", "delta": 1}
        ]
      }
    }]
  }
  | ]
]
--- error_log
OIDC url is not valid, uri:
