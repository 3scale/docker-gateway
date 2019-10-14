use lib 't';
use Test::APIcast 'no_plan';

run_tests();

__DATA__

=== TEST 1: request logs and response codes are not sent unless opt-in

--- http_config
  include $TEST_NGINX_UPSTREAM_CONFIG;
  lua_package_path "$TEST_NGINX_LUA_PATH";

  init_by_lua_block {
    require('apicast.configuration_loader').mock({
      services = {
        {
          id = 42,
          backend_version = 1,
          proxy = {
            api_backend = 'http://127.0.0.1:$TEST_NGINX_SERVER_PORT/api/',
            proxy_rules = {
              { pattern = '/', http_method = 'GET', metric_system_name = 'bar', delta = 1}
            }
          }
        },
      }
    })

    -- Response codes cannot be sent when the request is not cached. In that
    -- case, the authrep is called before calling the upstream, so the
    -- response code is not available. Response codes are only sent in the
    -- post-action phase. The cache is populated here to force a post-action
    -- phase.
    ngx.shared.api_keys:set('42:somekey:usage%5Bbar%5D=0', 200)
  }
  lua_shared_dict api_keys 1m;
--- config
  include $TEST_NGINX_APICAST_CONFIG;

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


=== TEST 2: response codes are sent when opt-in
--- main_config
env APICAST_RESPONSE_CODES=1;
--- http_config
  include $TEST_NGINX_UPSTREAM_CONFIG;
  lua_package_path "$TEST_NGINX_LUA_PATH";

  init_by_lua_block {
    require('apicast.configuration_loader').mock({
      services = {
        {
          id = 42,
          backend_version = 1,
          proxy = {
            api_backend = 'http://127.0.0.1:$TEST_NGINX_SERVER_PORT/api/',
            proxy_rules = {
              { pattern = '/', http_method = 'GET', metric_system_name = 'bar', delta = 1}
            }
          }
        },
      }
    })

    ngx.shared.api_keys:set('42:somekey:usage%5Bbar%5D=1', 200)
  }
  lua_shared_dict api_keys 1m;
--- config
  include $TEST_NGINX_APICAST_CONFIG;

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

=== TEST 3: response codes with multiple reporting threads
--- main_config
env APICAST_RESPONSE_CODES=1;
env APICAST_REPORTING_THREADS=4;
--- http_config
  include $TEST_NGINX_UPSTREAM_CONFIG;
  lua_package_path "$TEST_NGINX_LUA_PATH";

  init_by_lua_block {
    require('apicast.configuration_loader').mock({
      services = {
        {
          id = 42,
          backend_version = 1,
          proxy = {
            api_backend = 'http://127.0.0.1:$TEST_NGINX_SERVER_PORT/api/',
            proxy_rules = {
              { pattern = '/', http_method = 'GET', metric_system_name = 'bar', delta = 1}
            }
          }
        },
      }
    })

    ngx.shared.api_keys:set('42:somekey:usage%5Bbar%5D=1', 200)
  }
  lua_shared_dict api_keys 1m;
--- config
  include $TEST_NGINX_APICAST_CONFIG;

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
--- request eval
["GET /test?user_key=somekey", "GET /foo?user_key=somekey", "GET /?user_key=somekey"]
--- response_body eval
["api response\x{0a}", "api response\x{0a}", "api response\x{0a}"]
--- error_code eval
[ 201, 201, 201 ]
--- grep_error_log eval: qr/log\[\w+\]:.+/
--- grep_error_log_out eval
<<"END";
log[code]: 201
END
