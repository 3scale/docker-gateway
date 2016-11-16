use Test::Nginx::Socket::Lua 'no_plan';
use Cwd qw(cwd);
use Sys::Hostname;

my $pwd = cwd();
my $apicast = $ENV{TEST_NGINX_APICAST_PATH} || "$pwd/apicast";

our $host = hostname;
$ENV{TEST_NGINX_LUA_PATH} = "$apicast/src/?.lua;;";
$ENV{TEST_NGINX_UPSTREAM_CONFIG} = "$apicast/http.d/upstream.conf";
$ENV{TEST_NGINX_BACKEND_CONFIG} = "$apicast/conf.d/backend.conf";
$ENV{TEST_NGINX_APICAST_CONFIG} = "$apicast/conf.d/apicast.conf";

log_level('debug');
repeat_each(2);
no_root_location();
run_tests();

__DATA__

=== TEST 1: request logs and response codes are not sent unless opt-in

--- http_config
  include $TEST_NGINX_UPSTREAM_CONFIG;
  lua_package_path "$TEST_NGINX_LUA_PATH";

  init_by_lua_block {
    require('configuration').save({
      services = {
        {
          id = 42,
          backend_version = 1,
          proxy = {
            api_backend = 'http://127.0.0.1:$TEST_NGINX_SERVER_PORT/api/',
            proxy_rules = {
              { pattern = '/', http_method = 'GET', metric_system_name = 'bar' }
            }
          }
        },
      }
    })

    ngx.shared.api_keys:set('42:somekey:usage[bar]=0', 200)
  }
  lua_shared_dict api_keys 1m;
--- config
  include $TEST_NGINX_APICAST_CONFIG;

  set $backend_endpoint 'http://127.0.0.1:$TEST_NGINX_SERVER_PORT';

  location /api/ {
    echo "api response";
  }

  location /transactions/authrep.xml {
    content_by_lua_block {
      local args = ngx.req.get_uri_args()
      for key, val in pairs(args) do
        ngx.log(ngx.DEBUG, key, ": ", val)
      end
      ngx.exit(200)
    }
  }
--- request
GET /foo?user_key=somekey
--- response_body
api response
--- error_code: 200
--- grep_error_log eval: qr/log\[\w+\]:.+/
--- grep_error_log_out

=== TEST 2: request logs are sent when opt-in
--- main_config
env APICAST_REQUEST_LOGS=1;
--- http_config
  include $TEST_NGINX_UPSTREAM_CONFIG;
  lua_package_path "$TEST_NGINX_LUA_PATH";

  init_by_lua_block {
    require('configuration').save({
      services = {
        {
          id = 42,
          backend_version = 1,
          proxy = {
            api_backend = 'http://127.0.0.1:$TEST_NGINX_SERVER_PORT/api/',
            proxy_rules = {
              { pattern = '/', http_method = 'GET', metric_system_name = 'bar' }
            }
          }
        },
      }
    })

    ngx.shared.api_keys:set('42:somekey:usage[bar]=0', 200)
  }
  lua_shared_dict api_keys 1m;
--- config
  include $TEST_NGINX_APICAST_CONFIG;

  set $backend_endpoint 'http://127.0.0.1:$TEST_NGINX_SERVER_PORT';

  location /api/ {
    echo "api response";
  }

  location /transactions/authrep.xml {
    content_by_lua_block {
      local args = ngx.req.get_uri_args()
      for key, val in pairs(args) do
        ngx.log(ngx.DEBUG, key, ": ", val)
      end
      ngx.exit(200)
    }
  }
--- request
GET /foo?user_key=somekey
--- response_body
api response
--- error_code: 200
--- grep_error_log eval: qr/log\[\w+\]:.+/
--- grep_error_log_out eval
<<"END";
log[request]: {"path":"\\/foo?user_key=somekey","method":"GET","headers":{"host":"127.0.0.1","connection":"close"}}
log[response]: {"headers":{"x-3scale-matched-rules":"\\/","content-type":"text\\/plain","connection":"close","x-3scale-usage":"usage[bar]=0","x-3scale-hostname":"$::host","x-3scale-credentials":"user_key=somekey"},"body":"api response\\n"}
END


=== TEST 3: response codes are sent when opt-in
--- main_config
env APICAST_RESPONSE_CODES=1;
--- http_config
  include $TEST_NGINX_UPSTREAM_CONFIG;
  lua_package_path "$TEST_NGINX_LUA_PATH";

  init_by_lua_block {
    require('configuration').save({
      services = {
        {
          id = 42,
          backend_version = 1,
          proxy = {
            api_backend = 'http://127.0.0.1:$TEST_NGINX_SERVER_PORT/api/',
            proxy_rules = {
              { pattern = '/', http_method = 'GET', metric_system_name = 'bar' }
            }
          }
        },
      }
    })

    ngx.shared.api_keys:set('42:somekey:usage[bar]=0', 200)
  }
  lua_shared_dict api_keys 1m;
--- config
  include $TEST_NGINX_APICAST_CONFIG;

  set $backend_endpoint 'http://127.0.0.1:$TEST_NGINX_SERVER_PORT';

  location /api/ {
    echo "api response";
    echo_status 201;
  }

  location /transactions/authrep.xml {
    content_by_lua_block {
      local args = ngx.req.get_uri_args()
      for key, val in pairs(args) do
        ngx.log(ngx.DEBUG, key, ": ", val)
      end
      ngx.exit(200)
    }
  }
--- request
GET /foo?user_key=somekey
--- response_body
api response
--- error_code: 201
--- grep_error_log eval: qr/log\[\w+\]:.+/
--- grep_error_log_out eval
<<"END";
log[code]: 201
END


=== TEST 4: request logs and response codes are sent when opt-in
--- main_config
env APICAST_REQUEST_LOGS=1;
env APICAST_RESPONSE_CODES=1;
--- http_config
  include $TEST_NGINX_UPSTREAM_CONFIG;
  lua_package_path "$TEST_NGINX_LUA_PATH";

  init_by_lua_block {
    require('configuration').save({
      services = {
        {
          id = 42,
          backend_version = 1,
          proxy = {
            api_backend = 'http://127.0.0.1:$TEST_NGINX_SERVER_PORT/api/',
            proxy_rules = {
              { pattern = '/', http_method = 'GET', metric_system_name = 'bar' }
            }
          }
        },
      }
    })

    ngx.shared.api_keys:set('42:somekey:usage[bar]=0', 200)
  }
  lua_shared_dict api_keys 1m;
--- config
  include $TEST_NGINX_APICAST_CONFIG;

  set $backend_endpoint 'http://127.0.0.1:$TEST_NGINX_SERVER_PORT';

  location /api/ {
    echo "api response";
    echo_status 202;
  }

  location /transactions/authrep.xml {
    content_by_lua_block {
      local args = ngx.req.get_uri_args()
      for key, val in pairs(args) do
        ngx.log(ngx.DEBUG, key, ": ", val)
      end
      ngx.exit(200)
    }
  }
--- request
GET /foo?user_key=somekey
--- response_body
api response
--- error_code: 202
--- grep_error_log eval: qr/log\[\w+\]:.+/
--- grep_error_log_out eval
<<"END";
log[response]: {"headers":{"x-3scale-matched-rules":"\\/","content-type":"text\\/plain","connection":"close","x-3scale-usage":"usage[bar]=0","x-3scale-hostname":"$::host","x-3scale-credentials":"user_key=somekey"},"body":"api response\\n"}
log[request]: {"path":"\\/foo?user_key=somekey","method":"GET","headers":{"host":"127.0.0.1","connection":"close"}}
log[code]: 202
END
