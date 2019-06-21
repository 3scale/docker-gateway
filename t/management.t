use lib 't';

use Test::APIcast 'no_plan';

run_tests();

__DATA__

=== TEST 1: readiness probe with saved configuration
When configuration is saved, readiness probe returns success.
--- main_config
env APICAST_MANAGEMENT_API=status;
--- http_config
  lua_package_path "$TEST_NGINX_LUA_PATH";

  init_by_lua_block {
    require('apicast.configuration_loader').global({ services = { { id = 42 } } })
  }
--- config
include $TEST_NGINX_MANAGEMENT_CONFIG;
--- request
GET /status/ready
--- response_headers
Content-Type: application/json; charset=utf-8
--- response_body
{"status":"ready","success":true}
--- error_code: 200
--- no_error_log
[error]

=== TEST 2: readiness probe without configuration
Should respond with error status and a reason.
--- main_config
env APICAST_MANAGEMENT_API=status;
--- http_config
  lua_package_path "$TEST_NGINX_LUA_PATH";
--- config
include $TEST_NGINX_MANAGEMENT_CONFIG;
--- request
GET /status/ready
--- response_headers
Content-Type: application/json; charset=utf-8
--- response_body
{"success":false,"status":"error","error":"not configured"}
--- error_code: 412
--- no_error_log
[error]

=== TEST 3: readiness probe with 0 services
Should respond with error status and a reason.
--- main_config
env APICAST_MANAGEMENT_API=status;
--- http_config
  lua_package_path "$TEST_NGINX_LUA_PATH";
  init_by_lua_block {
    require('apicast.configuration_loader').global({services = { }})
  }
--- config
  include $TEST_NGINX_MANAGEMENT_CONFIG;
--- request
GET /status/ready
--- response_headers
Content-Type: application/json; charset=utf-8
--- response_body
{"success":true,"status":"warning","warning":"no services"}
--- error_code: 200
--- no_error_log
[error]

=== TEST 4: liveness probe returns success
As it is always alive.
--- main_config
env APICAST_MANAGEMENT_API=status;
--- http_config
  lua_package_path "$TEST_NGINX_LUA_PATH";
--- config
  include $TEST_NGINX_MANAGEMENT_CONFIG;
--- request
GET /status/live
--- response_headers
Content-Type: application/json; charset=utf-8
--- response_body
{"status":"live","success":true}
--- error_code: 200
--- no_error_log
[error]

=== TEST 5: config endpoint returns the configuration
Endpoint that dumps the original configuration.
--- main_config
env APICAST_MANAGEMENT_API=debug;
--- http_config
  lua_package_path "$TEST_NGINX_LUA_PATH";

  init_by_lua_block {
    require('apicast.configuration_loader').global({ services = { { id = 42 } } })
  }
--- config
include $TEST_NGINX_MANAGEMENT_CONFIG;
--- request
GET /config
--- response_headers
Content-Type: application/json; charset=utf-8
--- response_body
{"services":[{"id":42}]}
--- error_code: 200
--- no_error_log
[error]

=== TEST 6: config endpoint can write configuration
And can be later retrieved.
--- main_config
env APICAST_MANAGEMENT_API=debug;
--- http_config
  lua_package_path "$TEST_NGINX_LUA_PATH";
--- config

  location = /test {
    echo_subrequest DELETE /config;
    echo_subrequest GET /config;
    echo_subrequest PUT /config -b '{"services":[{"id":42}]}';
    echo_subrequest GET /config;
  }

  include $TEST_NGINX_MANAGEMENT_CONFIG;
--- request
GET /test
--- response_body
{"status":"ok","config":null}
null
{"services":1,"status":"ok","config":{"services":[{"id":42}]}}
{"services":[{"id":42}]}
--- error_code: 200
--- no_error_log
[error]

=== TEST 7: unknown route
returns nice error
--- http_config
  lua_package_path "$TEST_NGINX_LUA_PATH";
--- config
include $TEST_NGINX_MANAGEMENT_CONFIG;
--- request
GET /foobar
--- response_body
Could not resolve GET /foobar - nil
--- error_code: 404
--- no_error_log
[error]

=== TEST 8: boot
exposes boot function
--- main_config
env THREESCALE_PORTAL_ENDPOINT=http://localhost.local:$TEST_NGINX_SERVER_PORT/config/;
env RESOLVER=127.0.0.1:$TEST_NGINX_RANDOM_PORT;
env APICAST_MANAGEMENT_API=debug;
--- http_config
  lua_package_path "$TEST_NGINX_LUA_PATH";
  init_by_lua_block {
      require('apicast.configuration_loader').global({ services = { { id = 42 } } })
  }
--- config
include $TEST_NGINX_MANAGEMENT_CONFIG;
--- request
POST /boot
--- response_body
{"status":"ok","config":{"services":[{"id":42}],"oidc":[false]}}
--- error_code: 200
--- udp_listen random_port env chomp
$TEST_NGINX_RANDOM_PORT
--- udp_reply dns
[ "localhost.local", "127.0.0.1", 60 ]
--- no_error_log
[error]

=== TEST 9: boot called twice
keeps the same configuration
--- main_config
env THREESCALE_PORTAL_ENDPOINT=http://localhost.local:$TEST_NGINX_SERVER_PORT/config/;
env RESOLVER=127.0.0.1:$TEST_NGINX_RANDOM_PORT;
env APICAST_MANAGEMENT_API=debug;
--- http_config
  lua_package_path "$TEST_NGINX_LUA_PATH";
  init_by_lua_block {
      require('apicast.configuration_loader').global({ services = { { id = 42 } } })
  }
--- config
include $TEST_NGINX_MANAGEMENT_CONFIG;
location = /test {
    echo_subrequest POST /boot;
    echo_subrequest POST /boot;
  }
--- request
POST /test
--- response_body
{"status":"ok","config":{"services":[{"id":42}],"oidc":[false]}}
{"status":"ok","config":{"services":[{"id":42}],"oidc":[false]}}
--- error_code: 200
--- udp_listen random_port env chomp
$TEST_NGINX_RANDOM_PORT
--- udp_reply dns
[ "localhost.local", "127.0.0.1", 60 ]
--- no_error_log
[error]


=== TEST 10: config endpoint can delete configuration
--- main_config
env APICAST_MANAGEMENT_API=debug;
--- http_config
  lua_package_path "$TEST_NGINX_LUA_PATH";
--- config

  location = /test {
    echo_subrequest PUT /config -b '{"services":[{"id":42}]}';
    echo_subrequest DELETE /config;
    echo_subrequest GET /config;
  }

  include $TEST_NGINX_MANAGEMENT_CONFIG;
--- request
GET /test
--- response_body
{"services":1,"status":"ok","config":{"services":[{"id":42}]}}
{"status":"ok","config":null}
null
--- error_code: 200
--- no_error_log
[error]

=== TEST 11: all endpoints use correct Content-Type
JSON response body and content type application/json should be returned.
--- main_config
env APICAST_MANAGEMENT_API=debug;
--- http_config
  lua_package_path "$TEST_NGINX_LUA_PATH";
--- config
  include $TEST_NGINX_MANAGEMENT_CONFIG;
--- request eval
[ 'DELETE /config', 'PUT /config 
{"services":[{"id":42}]}', 'POST /config
{"services":[{"id":42}]}', 'GET /config' ]
--- response_headers eval
[ 'Content-Type: application/json; charset=utf-8',
  'Content-Type: application/json; charset=utf-8',
  'Content-Type: application/json; charset=utf-8', 
  'Content-Type: application/json; charset=utf-8' ]
--- response_body eval
[ '{"status":"ok","config":null}'."\n",
  '{"services":1,"status":"ok","config":{"services":[{"id":42}]}}'."\n",
  '{"services":1,"status":"ok","config":{"services":[{"id":42}]}}'."\n",
  '{"services":[{"id":42}]}'."\n" ]  
--- no_error_log
[error]


=== TEST 12: GET /dns/cache
JSON response of the internal DNS cache.
--- main_config
env APICAST_MANAGEMENT_API=debug;
--- http_config
lua_package_path "$TEST_NGINX_LUA_PATH";
init_by_lua_block {
  ngx.now = function() return 0 end
  local cache = require('resty.resolver.cache').shared():save({ {
    address = "127.0.0.1",
    class = 1,
    name = "127.0.0.1.xip.io",
    section = 1,
    ttl = 199,
    type = 1
  }})
}
--- config
  include $TEST_NGINX_MANAGEMENT_CONFIG;
--- request
GET /dns/cache
--- response_headers
Content-Type: application/json; charset=utf-8
--- expected_response_body_like_multiple eval
[[
    qr/"name":"127.0.0.1.xip.io"/,
    qr/\{"127.0.0.1.xip.io":\{"value":{"1":{"address":"127.0.0.1","class":1,"ttl":199/,
]]
--- no_error_log
[error]


=== TEST 13: liveness status is not accessible
Unless the APICAST_MANAGEMENT_API is set to 'status'.
--- main_config
env APICAST_MANAGEMENT_API=disabled;
--- http_config
  lua_package_path "$TEST_NGINX_LUA_PATH";
--- config
  include $TEST_NGINX_MANAGEMENT_CONFIG;
--- request
GET /status/live
--- error_code: 404
--- no_error_log
[error]

=== TEST 14: config endpoint is not accessible
Unless the APICAST_MANAGEMENT_API is set to 'debug'.
--- main_config
env APICAST_MANAGEMENT_API=status;
--- http_config
  lua_package_path "$TEST_NGINX_LUA_PATH";

  init_by_lua_block {
    require('apicast.configuration_loader').global({ services = { { id = 42 } } })
  }
--- config
include $TEST_NGINX_MANAGEMENT_CONFIG;
--- request
GET /config
--- error_code: 404
--- no_error_log
[error]

=== TEST 15: writing invalid configuration
JSON should be validated before trying to save it.
--- main_config
env APICAST_MANAGEMENT_API=debug;
--- http_config
lua_package_path "$TEST_NGINX_LUA_PATH";
--- config
include $TEST_NGINX_MANAGEMENT_CONFIG;
--- request
POST /config
invalid json
--- response_body
{"config":null,"status":"error","error":"Expected value but found invalid token at character 1"}
--- error_code: 400
--- no_error_log
[error]


=== TEST 16: writing wrong configuration
JSON is valid but it not a configuration.
--- main_config
env APICAST_MANAGEMENT_API=debug;
--- http_config
lua_package_path "$TEST_NGINX_LUA_PATH";
--- config
include $TEST_NGINX_MANAGEMENT_CONFIG;
--- request
POST /config
{"id":42}
--- response_body
{"services":0,"config":{"id":42},"status":"not_configured"}
--- error_code: 406
--- no_error_log
[error]

=== TEST 17: status information
Has information about timers and time.
--- main_config
env APICAST_MANAGEMENT_API=status;
--- http_config
  lua_package_path "$TEST_NGINX_LUA_PATH";
--- config
include $TEST_NGINX_MANAGEMENT_CONFIG;
--- request
GET /status/info
--- response_body
{"timers":{"running":0,"pending":0},"worker":{"exiting":false,"count":1,"id":0}}
--- error_code: 200
--- no_error_log
[error]
