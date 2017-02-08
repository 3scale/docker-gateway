use Test::Nginx::Socket::Lua 'no_plan';
use Cwd qw(cwd);

my $pwd = cwd();
my $apicast = $ENV{TEST_NGINX_APICAST_PATH} || "$pwd/apicast";

$ENV{TEST_NGINX_LUA_PATH} = "$apicast/src/?.lua;;";
$ENV{TEST_NGINX_UPSTREAM_CONFIG} = "$apicast/http.d/upstream.conf";
$ENV{TEST_NGINX_BACKEND_CONFIG} = "$apicast/conf.d/backend.conf";
$ENV{TEST_NGINX_APICAST_CONFIG} = "$apicast/conf.d/apicast.conf";

log_level('debug');
repeat_each(2);
no_root_location();
run_tests();

__DATA__

=== TEST 1: multi service configuration limited to specific service
--- main_config
env APICAST_SERVICES=42,21;
--- http_config
  include $TEST_NGINX_UPSTREAM_CONFIG;
  lua_package_path "$TEST_NGINX_LUA_PATH";
  init_by_lua_block {
    require('configuration_loader').save({
      services = {
        {
          id = 42,
          backend_version = 1,
          proxy = {
            api_backend = "http://127.0.0.1:$TEST_NGINX_SERVER_PORT/api-backend/one/",
            hosts = { 'one' },
            proxy_rules = {
              { pattern = '/', http_method = 'GET', metric_system_name = 'one', delta = 1 }
            }
          }
        },
        {
          id = 11,
          proxy = {
            hosts = { 'two' }
          }
        }
      }
    })
  }
  lua_shared_dict api_keys 10m;
--- config
  include $TEST_NGINX_APICAST_CONFIG;

  set $backend_endpoint 'http://127.0.0.1:$TEST_NGINX_SERVER_PORT';

  location /transactions/authrep.xml {
    content_by_lua_block { ngx.exit(200) }
  }

  location ~ /api-backend(/.+) {
     echo 'yay, api backend: $1';
  }
--- pipelined_requests eval
["GET /?user_key=1","GET /?user_key=2"]
--- more_headers eval
["Host: one", "Host: two"]
--- response_body eval
["yay, api backend: /one/\n", ""]
--- error_code eval
[200, 404]
