use lib 't';
use Test::APIcast 'no_plan';

BEGIN {
    $ENV{APICAST_POLICY_LOAD_PATH} = 't/fixtures/policies';
}

env_to_nginx(
    'APICAST_POLICY_LOAD_PATH'
);

run_tests();

__DATA__

=== TEST 1: custom policy chain
This test uses the phase logger policy to verify that all of its phases are run
when we use a policy chain that contains it. The policy chain also contains the
normal apicast policy, so we can check that the authorize flow continues working.
Phases init and init_worker do not appear in the test because they're run just
once, not on every request.

--- http_config
  include $TEST_NGINX_UPSTREAM_CONFIG;
  lua_package_path "$TEST_NGINX_LUA_PATH";
  init_by_lua_block {
    require('apicast.configuration_loader').mock({
      services = {
        {
          id = 42,
          backend_version = 1,
          backend_authentication_type = 'service_token',
          backend_authentication_value = 'token-value',
          proxy = {
            policy_chain = { { name = 'apicast.policy.phase_logger' }, { name = 'apicast.policy.apicast' } },
            api_backend = "http://127.0.0.1:$TEST_NGINX_SERVER_PORT/api-backend/",
            proxy_rules = {
              {
                http_method = "GET",
                pattern = "/test",
                metric_system_name = "hits",
                delta = 1
              }
            }
          }
        }
      }
    })
  }

--- config
  include $TEST_NGINX_APICAST_CONFIG;

  location /transactions/authrep.xml {
    content_by_lua_block { ngx.exit(200) }
  }

  location /api-backend/ {
     echo 'yay, api backend';
  }
--- request
GET /test?user_key=abc
--- response_body
yay, api backend
--- error_code: 200
--- no_error_log
[error]
--- error_log chomp
running phase: rewrite
running phase: access
running phase: content
running phase: balancer
running phase: header_filter
running phase: body_filter
running phase: post_action
running phase: log



=== TEST 2: custom policy chain responds with content
This tests uses phase logger policy to verify all needed phases are executed.
When some policy responds with content header_filter, body_filter and post_actions should
still be executed.

--- http_config
  include $TEST_NGINX_UPSTREAM_CONFIG;
  lua_package_path "$TEST_NGINX_LUA_PATH";
  init_by_lua_block {
    require('apicast.configuration_loader').mock({
      services = {
        {
          id = 42,
          backend_version = 1,
          backend_authentication_type = 'service_token',
          backend_authentication_value = 'token-value',
          proxy = {
            policy_chain = { { name = 'apicast.policy.phase_logger' }, { name = 'apicast.policy.echo' } },
            api_backend = "http://127.0.0.1:$TEST_NGINX_SERVER_PORT/api-backend/",
            proxy_rules = {
              {
                http_method = "GET",
                pattern = "/test",
                metric_system_name = "hits",
                delta = 1
              }
            }
          }
        }
      }
    })
  }

--- config
  include $TEST_NGINX_APICAST_CONFIG;

  location /transactions/authrep.xml {
    content_by_lua_block { ngx.exit(200) }
  }

  location /api-backend/ {
     echo 'yay, api backend';
  }
--- request
GET /test
--- response_body
GET /test HTTP/1.1
--- error_code: 200
--- no_error_log
[error]
--- error_log chomp
running phase: rewrite
running phase: access
running phase: content
running phase: header_filter
running phase: body_filter
running phase: post_action
running phase: log


=== TEST 3: null policy chain
When policy chain is null, the default Apicast plugin is used and authorizes
as expected.
--- http_config
  include $TEST_NGINX_UPSTREAM_CONFIG;
  lua_package_path "$TEST_NGINX_LUA_PATH";
  init_by_lua_block {
    require('apicast.configuration_loader').mock({
      services = {
        {
          id = 42,
          backend_version = 1,
          backend_authentication_type = 'service_token',
          backend_authentication_value = 'token-value',
          proxy = {
            policy_chain = ngx.null,
            api_backend = "http://127.0.0.1:$TEST_NGINX_SERVER_PORT/api-backend/",
            proxy_rules = {
              {
                http_method = "GET",
                pattern = "/test",
                metric_system_name = "hits",
                delta = 1
              }
            }
          }
        }
      }
    })
  }

--- config
  include $TEST_NGINX_APICAST_CONFIG;

  location /transactions/authrep.xml {
    content_by_lua_block { ngx.exit(200) }
  }

  location /api-backend/ {
     echo 'yay, api backend';
  }
--- request
GET /test?user_key=abc
--- response_body
yay, api backend
--- error_code: 200
--- no_error_log
[error]



=== TEST 4: policy chain with invalid elements
Invalid policies are removed from the chain.
--- http_config
  include $TEST_NGINX_UPSTREAM_CONFIG;
  lua_package_path "$TEST_NGINX_LUA_PATH";
  init_by_lua_block {
    require('apicast.configuration_loader').mock({
      services = {
        {
          id = 42,
          backend_version = 1,
          backend_authentication_type = 'service_token',
          backend_authentication_value = 'token-value',
          proxy = {
            policy_chain = {
              { name = 'apicast.policy.phase_logger' },
              { name = 'invalid' },
              { name = 'apicast.policy.echo' }
            },
            api_backend = "http://127.0.0.1:$TEST_NGINX_SERVER_PORT/api-backend/",
            proxy_rules = {
              {
                http_method = "GET",
                pattern = "/test",
                metric_system_name = "hits",
                delta = 1
              }
            }
          }
        }
      }
    })
  }

--- config
  include $TEST_NGINX_APICAST_CONFIG;

  location /transactions/authrep.xml {
    content_by_lua_block { ngx.exit(200) }
  }
--- request
GET /test
--- response_body
GET /test HTTP/1.1
--- error_log chomp
running phase: rewrite
running phase: access
running phase: content
running phase: header_filter
running phase: body_filter
running phase: post_action
running phase: log
--- error_code: 200
--- no_error_log
[error]

=== TEST 5: policy chain with a policy that crashes on new()
Policies that crash when initialized should be removed from the chain
--- http_config
  include $TEST_NGINX_UPSTREAM_CONFIG;
  lua_package_path "$TEST_NGINX_LUA_PATH";
  init_by_lua_block {
    require('apicast.configuration_loader').mock({
      services = {
        {
          id = 42,
          proxy = {
            policy_chain = {
              { name = 'error_policy', version = '1.0.0' },
              { name = 'apicast.policy.echo' }
            }
          }
        }
      }
    })
  }

--- config
  include $TEST_NGINX_APICAST_CONFIG;

  location /transactions/authrep.xml {
    content_by_lua_block { ngx.exit(200) }
  }
--- request
GET /test
--- response_body
GET /test HTTP/1.1
--- error_code: 200
--- error_log
Policy error_policy crashed in .new()
