use Test::Nginx::Socket::Lua 'no_plan';
use Cwd qw(cwd);

my $pwd = cwd();
my $apicast = $ENV{TEST_NGINX_APICAST_PATH} || "$pwd/apicast";

$ENV{TEST_NGINX_LUA_PATH} = "$apicast/src/?.lua;;";
$ENV{TEST_NGINX_UPSTREAM_CONFIG} = "$apicast/http.d/upstream.conf";
$ENV{TEST_NGINX_BACKEND_CONFIG} = "$apicast/conf.d/backend.conf";
$ENV{TEST_NGINX_APICAST_CONFIG} = "$apicast/conf.d/apicast.conf";

log_level('debug');
repeat_each(1); # Can't be 2 as the second run would hit the cache
no_root_location();
run_tests();

__DATA__

=== TEST 1: multi service configuration with path based routing
Two services can exist together and are split by their hostname and mapping rules.
--- main_config
env APICAST_PATH_ROUTING_ENABLED=1;
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
            hosts = { 'same' },
            backend_authentication_type = 'service_token',
            backend_authentication_value = 'service-one',
            proxy_rules = {
              { pattern = '/one', http_method = 'GET', metric_system_name = 'one', delta = 1 }
            }
          }
        },
        {
          id = 21,
          backend_version = 2,
          proxy = {
            api_backend = "http://127.0.0.1:$TEST_NGINX_SERVER_PORT/api-backend/two/",
            hosts = { 'same' },
            backend_authentication_type = 'service_token',
            backend_authentication_value = 'service-two',
            proxy_rules = {
              { pattern = '/two', http_method = 'GET', metric_system_name = 'two', delta = 2 }
            }
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

  location ~ /test/(.+) {
    proxy_pass $scheme://127.0.0.1:$server_port/$1$is_args$args;
    proxy_set_header Host same;
  }

  location = /t {
    echo_subrequest GET /test/one -q user_key=one-key;
    echo_subrequest GET /test/two -q app_id=two-id&app_key=two-key;
  }
--- request
GET /t
--- response_body
yay, api backend: /one/
yay, api backend: /two/
--- error_code: 200
--- grep_error_log eval: qr/apicast cache (?:hit|miss|write) key: [^,\s]+/
--- grep_error_log_out
apicast cache miss key: 42:one-key:usage[one]=1
apicast cache write key: 42:one-key:usage[one]=1
apicast cache miss key: 21:two-id:two-key:usage[two]=2
apicast cache write key: 21:two-id:two-key:usage[two]=2
