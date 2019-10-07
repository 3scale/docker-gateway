use lib 't';
use Test::APIcast 'no_plan';

run_tests();

__DATA__

=== TEST 1: call to backend is cached
First call is done synchronously and the second out of band.
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
            api_backend = "http://127.0.0.1:$TEST_NGINX_SERVER_PORT/api-backend/",
            proxy_rules = {
              { id = 1, http_method = "GET",
                pattern = "/{env}/video/encode?size={size}&speed=2x",
                metric_system_name = "weeee", delta = 1,
                parameters = { "env" },
                querystring_parameters = { size = "{size}", speed = "2x" }
              }
            }
          }
        }
      }
    })
  }
  lua_shared_dict api_keys 10m;
--- config
  include $TEST_NGINX_APICAST_CONFIG;

  location /transactions/authrep.xml {
    content_by_lua_block { ngx.exit(200) }
  }

  location /api-backend/ {
     echo 'yay, api backend';
  }
--- request
GET /staging/video/encode?size=100&speed=3x&user_key=foo&speed=2x
--- response_body
yay, api backend
--- error_code: 200

=== TEST 2: mapping rules when POST request has url parms
url params in a POST call are taken into account when matching mapping rules.

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
          backend_authentication_value = 'my-token',
          proxy = {
            api_backend = 'http://127.0.0.1:$TEST_NGINX_SERVER_PORT/api/',
            proxy_rules = {
              { pattern = '/foo?bar=baz',
                querystring_parameters = { bar = 'baz' },
                http_method = 'POST',
                metric_system_name = 'bar',
                delta = 7 }
            }
          }
        },
      }
    })
  }
--- config
  include $TEST_NGINX_APICAST_CONFIG;

  location /api/ {
    echo "api response";
  }

  location /transactions/authrep.xml {
    content_by_lua_block { ngx.exit(200) }
  }
--- request
POST /foo?bar=baz&user_key=somekey
--- more_headers
X-3scale-Debug: my-token
--- response_body
api response
--- error_code: 200
--- response_headers
X-3scale-matched-rules: /foo?bar=baz
X-3scale-usage: usage%5Bbar%5D=7

=== TEST 3: mapping rules when POST request has body params
request body params in a POST call are taken into account when matching mapping rules.

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
          backend_authentication_value = 'my-token',
          proxy = {
            api_backend = 'http://127.0.0.1:$TEST_NGINX_SERVER_PORT/api/',
            proxy_rules = {
              { pattern = '/foo?bar=baz',
                querystring_parameters = { bar = 'baz' },
                http_method = 'POST',
                metric_system_name = 'bar',
                delta = 7 }
            }
          }
        },
      }
    })
  }
--- config
  include $TEST_NGINX_APICAST_CONFIG;

  location /api/ {
    echo "api response";
  }

  location /transactions/authrep.xml {
    content_by_lua_block { ngx.exit(200) }
  }
--- request
POST /foo?user_key=somekey
bar=baz
--- more_headers
X-3scale-Debug: my-token
--- response_body
api response
--- error_code: 200
--- response_headers
X-3scale-matched-rules: /foo?bar=baz
X-3scale-usage: usage%5Bbar%5D=7

=== TEST 4: mapping rules when POST request has body params and url params
Both body params and url params are taken into account when matching mapping
rules. When a param is both in the url and the body, the one in the body takes
precedence.

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
          backend_authentication_value = 'my-token',
          proxy = {
            api_backend = 'http://127.0.0.1:$TEST_NGINX_SERVER_PORT/api/',
            proxy_rules = {
              { pattern = '/foo?a_param=val1&another_param=val2',
                querystring_parameters = { a_param = 'val1', another_param = 'val2' },
                http_method = 'POST',
                metric_system_name = 'bar',
                delta = 7 }
            }
          }
        },
      }
    })
  }
--- config
  include $TEST_NGINX_APICAST_CONFIG;

  location /api/ {
    echo "api response";
  }

  location /transactions/authrep.xml {
    content_by_lua_block { ngx.exit(200) }
  }
--- request
POST /foo?a_param=val3&another_param=val2&user_key=somekey
a_param=val1
--- more_headers
X-3scale-Debug: my-token
--- response_body
api response
--- error_code: 200
--- response_headers
X-3scale-matched-rules: /foo?a_param=val1&another_param=val2
X-3scale-usage: usage%5Bbar%5D=7

=== TEST 5: mapping rules with "last" attribute
Mapping rules can have a "last" attribute. When this attribute is set to true,
and the rule matches, it indicates that the matcher should stop processing the
rules that come after.
In the example, we have 4 rules:
- the first one matches and last = false, so the matcher will continue.
- the second has last = true but does not match, so the matcher will continue.
- the third one matches and has last = true so the matcher will stop here.
The usage is checked in the 3scale backend endpoint.
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
            api_backend = "http://127.0.0.1:$TEST_NGINX_SERVER_PORT/api-backend/",
            proxy_rules = {
              {
                last = false,
                id = 1,
                http_method = "GET",
                pattern = "/",
                metric_system_name = "hits",
                delta = 1
              },
              {
                last = true,
                id = 2,
                http_method = "GET",
                pattern = "/i_dont_match",
                metric_system_name = "hits",
                delta = 100
              },
              {
                last = true,
                id = 3,
                http_method = "GET",
                pattern = "/abc",
                metric_system_name = "hits",
                delta = 2
              },
              {
                id = 4,
                http_method = "GET",
                pattern = "/abc/def",
                metric_system_name = "hits",
                delta = 10
              }
            }
          }
        }
      }
    })
  }
  lua_shared_dict api_keys 10m;
--- config
  include $TEST_NGINX_APICAST_CONFIG;

  location /transactions/authrep.xml {
    content_by_lua_block {
      local hits = tonumber(ngx.req.get_uri_args()["usage[hits]"])
      require('luassert').equals(3, hits) -- rule 1 + rule 3
    }
  }

  location /api-backend/ {
     echo 'yay, api backend';
  }
--- request
GET /abc/def?user_key=uk
--- response_body
yay, api backend
--- error_code: 200

=== TEST 6: request uri with special chars
Call with special chars and validate that are correctly matched.
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
            api_backend = "http://127.0.0.1:$TEST_NGINX_SERVER_PORT/api-backend/",
            proxy_rules = {
              { id = 1, http_method = "GET",
                pattern = "/foo%20/bar/",
                metric_system_name = "weeee", delta = 1,
              }
            }
          }
        }
      }
    })
  }
  lua_shared_dict api_keys 10m;
--- config
  include $TEST_NGINX_APICAST_CONFIG;

  location /transactions/authrep.xml {
    content_by_lua_block { ngx.exit(200) }
  }

  location /api-backend/ {
     echo 'yay, api backend';
  }
--- request
GET /foo%20/bar/?user_key=foo
--- response_body
yay, api backend
--- error_code: 200
