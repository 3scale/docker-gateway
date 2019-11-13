use lib 't';
use Test::APIcast 'no_plan';

$ENV{TEST_NGINX_REDIS_HOST} ||= $ENV{REDIS_HOST} || "127.0.0.1";
$ENV{BACKEND_ENDPOINT_OVERRIDE} ||= "http://127.0.0.1:$Test::Nginx::Util::ServerPortForClient/backend";

env_to_nginx('BACKEND_ENDPOINT_OVERRIDE');

run_tests();

__DATA__

=== TEST 1: calling /authorize redirects with error when credentials are missing
--- http_config
  include $TEST_NGINX_UPSTREAM_CONFIG;
  lua_package_path "$TEST_NGINX_LUA_PATH";

  init_by_lua_block {
    require('apicast.configuration_loader').mock({
      services = {
        { backend_version = 'oauth',
          proxy = { oauth_login_url = "http://example.com/redirect" } }
      }
    })
  }
--- config
  include $TEST_NGINX_APICAST_CONFIG;

  location /backend/transactions/oauth_authorize.xml {
    content_by_lua_block {
      ngx.log(ngx.WARN, 'called oauth_authorize.xml')
      ngx.exit(403)
    }
  }
--- request
GET /authorize
--- error_code: 302
--- response_headers
Location: http://example.com/redirect?error=invalid_client
--- error_log
called oauth_authorize.xml
--- no_error_log
[error]

=== TEST 2: calling /authorize works (Authorization Code)
[Section 1.3.1 of RFC 6749](https://tools.ietf.org/html/rfc6749#section-1.3.1)
--- main_config
  env REDIS_HOST=$TEST_NGINX_REDIS_HOST;
--- http_config
  include $TEST_NGINX_UPSTREAM_CONFIG;
  lua_package_path "$TEST_NGINX_LUA_PATH";

  init_by_lua_block {
    require('apicast.configuration_loader').mock({
      services = {
        { id = 42, backend_version = 'oauth',
          backend_authentication_type = 'provider_key',
          backend_authentication_value = 'fookey',
          proxy = { oauth_login_url = "http://example.com/redirect" } }
      }
    })
  }
--- config
  include $TEST_NGINX_APICAST_CONFIG;

  location = /backend/transactions/oauth_authorize.xml {
    content_by_lua_block {
      local expected = "provider_key=fookey&service_id=42&app_id=id&redirect_uri=otheruri"
      require('luassert').same(ngx.decode_args(expected), ngx.req.get_uri_args(0))
      ngx.say('<?xml version="1.0" encoding="UTF-8"?><status><authorized>true</authorized></status>')
    }
  }
--- request
GET /authorize?client_id=id&redirect_uri=otheruri&response_type=code&scope=whatever&state=123456
--- error_code: 302
--- response_headers_like
Location: http://example.com/redirect\?response_type=code&client_id=id&state=[a-z0-9]{40}&scope=whatever&tok=\w+&redirect_uri=otheruri
--- no_error_log
[error]

=== TEST 3: calling /authorize works (Implicit)
[Section 1.3.2 of RFC 6749](https://tools.ietf.org/html/rfc6749#section-1.3.2)
--- http_config
  include $TEST_NGINX_UPSTREAM_CONFIG;
  lua_package_path "$TEST_NGINX_LUA_PATH";

  init_by_lua_block {
    require('apicast.configuration_loader').mock({
      services = {
        {
         id = 42, backend_version = 'oauth',
         backend_authentication_type = 'provider_key',
         backend_authentication_value = 'fookey',
         proxy = { oauth_login_url = "http://example.com/redirect" }
        }
      }
    })
  }
--- config
  include $TEST_NGINX_APICAST_CONFIG;

  location = /backend/transactions/oauth_authorize.xml {
    content_by_lua_block {
      local expected = "provider_key=fookey&service_id=42&app_id=id&redirect_uri=otheruri"
      require('luassert').same(ngx.decode_args(expected), ngx.req.get_uri_args(0))
      ngx.say('<?xml version="1.0" encoding="UTF-8"?><status><authorized>true</authorized></status>')
    }
  }
--- request
GET /authorize?client_id=id&redirect_uri=otheruri&response_type=token&scope=whatever
--- error_code: 302
--- response_headers_like
Location: http://example.com/redirect\?response_type=token&client_id=id&scope=whatever&redirect_uri=otheruri&error=unsupported_response_type
--- no_error_log
[error]

=== TEST 4: calling /oauth/token returns correct error message on missing parameters
--- http_config
  include $TEST_NGINX_UPSTREAM_CONFIG;
  lua_package_path "$TEST_NGINX_LUA_PATH";
  init_by_lua_block {
    require('apicast.configuration_loader').mock({
      services = {
        { backend_version = 'oauth' }
      }
    })
  }
--- config
include $TEST_NGINX_APICAST_CONFIG;

location /backend/transactions/oauth_authorize.xml {
  content_by_lua_block {
    ngx.log(ngx.WARN, 'called oauth_authorize.xml')
    ngx.exit(403)
  }
}
--- request
POST /oauth/token
--- response_body chomp
{"error":"invalid_client"}
--- error_code: 401
--- no_error_log
[error]
--- error_log
called oauth_authorize.xml

=== TEST 5: calling /oauth/token returns correct error message on invalid parameters
--- http_config
  include $TEST_NGINX_UPSTREAM_CONFIG;
  lua_package_path "$TEST_NGINX_LUA_PATH";
  init_by_lua_block {
    require('apicast.configuration_loader').mock({
      services = {
        { backend_version = 'oauth' }
      }
    })
  }
--- config
include $TEST_NGINX_APICAST_CONFIG;

location /backend/transactions/oauth_authorize.xml {
  content_by_lua_block {
    ngx.log(ngx.WARN, 'called oauth_authorize.xml')
    ngx.exit(403)
  }
}
--- request
POST /oauth/token?grant_type=authorization_code&client_id=client_id&redirect_uri=redirect_uri&client_secret=client_secret&code=code
--- response_body chomp
{"error":"invalid_client"}
--- error_code: 401
--- no_error_log
[error]
--- error_log
called oauth_authorize.xml

=== TEST 6: calling /callback without params returns correct error message
--- http_config
  lua_package_path "$TEST_NGINX_LUA_PATH";
  init_by_lua_block {
    require('apicast.configuration_loader').mock({
      services = {
        { backend_version = 'oauth' }
      }
    })
  }
--- config
include $TEST_NGINX_APICAST_CONFIG;
--- request
GET /callback
--- response_body chomp
{"error":"missing redirect_uri"}
--- error_code: 400
--- no_error_log
[error]

=== TEST 7: calling /callback redirects to correct error when state is missing
--- http_config
  lua_package_path "$TEST_NGINX_LUA_PATH";
  init_by_lua_block {
    require('apicast.configuration_loader').mock({
      services = {
        { backend_version = 'oauth' }
      }
    })
  }
--- config
include $TEST_NGINX_APICAST_CONFIG;
--- request eval
"GET /callback?redirect_uri=http://127.0.0.1:$ENV{TEST_NGINX_SERVER_PORT}/redirect_uri"
--- error_code: 302
--- response_headers eval
"Location: http://127.0.0.1:$ENV{TEST_NGINX_SERVER_PORT}/redirect_uri#error=invalid_request&error_description=missing_state"
--- response_body_like chomp
^<html>
--- no_error_log
[error]

=== TEST 8: calling /callback redirects to correct error when state is missing
--- main_config
  env REDIS_HOST=$TEST_NGINX_REDIS_HOST;
--- http_config
  lua_package_path "$TEST_NGINX_LUA_PATH";
  init_by_lua_block {
    require('apicast.configuration_loader').mock({
      services = {
        { backend_version = 'oauth' }
      }
    })
  }
--- config
include $TEST_NGINX_APICAST_CONFIG;
--- request eval
"GET /callback?redirect_uri=http://127.0.0.1:$ENV{TEST_NGINX_SERVER_PORT}/redirect_uri&state=foo"
--- error_code: 302
--- response_headers eval
"Location: http://127.0.0.1:$ENV{TEST_NGINX_SERVER_PORT}/redirect_uri#error=invalid_request&error_description=invalid_or_expired_state&state=foo"
--- no_error_log
[error]

=== TEST 9: calling /callback works
Not part of the RFC. This is the Gateway API to create access tokens and redirect back to the Client.
--- main_config
  env REDIS_HOST=$TEST_NGINX_REDIS_HOST;
--- http_config
  lua_package_path "$TEST_NGINX_LUA_PATH";
  init_by_lua_block {
    require('apicast.configuration_loader').mock({
      services = {
        { id = 42, backend_version = 'oauth', oauth_login_url = "" }
      }
    })
  }
--- config
  include $TEST_NGINX_APICAST_CONFIG;

  location = /fake-authorize {
    content_by_lua_block {
      local authorize = require('apicast.oauth.apicast_oauth.authorize')
      local redirect_uri = 'http://example.com/redirect'
      local nonce = authorize.persist_nonce(42, {
        client_id = 'foo',
        state = 'somestate',
        redirect_uri = redirect_uri,
        scope = 'plan',
        client_state='clientstate'
      })
      ngx.exec('/callback?redirect_uri=' .. redirect_uri .. '&state=' .. nonce)
    }
  }
--- request
GET /fake-authorize
--- error_code: 302
--- no_error_log
[error]
--- response_body_like chomp
^<html>
--- response_headers_like
Location: http://example.com/redirect\?code=\w+&state=clientstate

=== TEST 10: calling /oauth/token returns correct error message on invalid parameters
--- main_config
  env REDIS_HOST=$TEST_NGINX_REDIS_HOST;
  env APICAST_OAUTH_TOKENS_TTL=123;
--- http_config
  include $TEST_NGINX_UPSTREAM_CONFIG;
  lua_package_path "$TEST_NGINX_LUA_PATH";
  init_by_lua_block {
    require('apicast.configuration_loader').mock({
      services = {
        { id = 42, backend_version = 'oauth',
         backend_authentication_type = 'provider_key',
         backend_authentication_value = 'fookey'
        }
      }
    })
  }
--- config
  include $TEST_NGINX_APICAST_CONFIG;


  location = /t {
    content_by_lua_block {
      local authorize = require('apicast.oauth.apicast_oauth.authorize')
      local authorized_callback = require('apicast.oauth.apicast_oauth.authorized_callback')
      local redirect_uri = 'http://example.com/redirect'
      local nonce = authorize.persist_nonce(42, {
        client_id = 'foo',
        state = 'somestate',
        redirect_uri = redirect_uri,
        scope = 'plan'
      })
      local client_data = authorized_callback.retrieve_client_data(42, { state = nonce })
      local code = authorized_callback.generate_code(client_data)

      assert(authorized_callback.persist_code(client_data, { state = 'somestate', user_id = 'someuser', redirect_uri = 'redirect_uri' }, code))

      ngx.req.set_method(ngx.HTTP_POST)
      ngx.req.read_body()
      ngx.req.set_body_data('grant_type=authorization_code&client_id=client_id&redirect_uri=redirect_uri&client_secret=client_secret&code=' .. code)
      ngx.exec('/oauth/token')
    }
  }

    location = /backend/transactions/oauth_authorize.xml {
      content_by_lua_block {
        local expected = "provider_key=fookey&service_id=42&app_key=client_secret&app_id=client_id&redirect_uri=redirect_uri"
        require('luassert').same(ngx.decode_args(expected), ngx.req.get_uri_args(0))
        ngx.say('<?xml version="1.0" encoding="UTF-8"?><status><authorized>true</authorized><application><key>client_secret</key></application></status>')
      }
    }

    location = /backend/services/42/oauth_access_tokens.xml {
      client_body_timeout 1s;
      content_by_lua_block {
        ngx.req.read_body()
        local ttl = tonumber(ngx.req.get_post_args()['ttl'])
        if ttl ~= 123 then
          ngx.log(ngx.ERR, 'Backend did not receive the correct TTL.')
          ngx.exit(400)
        else
          ngx.exit(200)
        end
      }
    }
--- request
GET /t
--- response_body_like
{"token_type":"bearer","expires_in":123,"access_token":"\w+"}
--- error_code: 200
--- no_error_log
[error]

=== TEST 11: calling with correct access_token in query proxies to the api upstream
--- http_config
  lua_package_path "$TEST_NGINX_LUA_PATH";
  include $TEST_NGINX_UPSTREAM_CONFIG;

  init_by_lua_block {
    require('apicast.configuration_loader').mock({
      services = {
        {
          backend_version = 'oauth',
          proxy = {
            credentials_location = "query",
            api_backend = "http://127.0.0.1:$TEST_NGINX_SERVER_PORT/api-backend/",
            proxy_rules = {
              { pattern = '/', http_method = 'GET', metric_system_name = 'hits', delta=1}
            }
          }
        }
      }
    })

    ngx.shared.api_keys:set('default:foobar:usage%5Bhits%5D=0', 200)
  }
  lua_shared_dict api_keys 1m;
--- config
  include $TEST_NGINX_APICAST_CONFIG;
  include $TEST_NGINX_BACKEND_CONFIG;

  location /api-backend/ {
    echo "yay, upstream";
  }

  location = /backend/transactions/oauth_authrep.xml {
    echo 'ok';
  }
--- request
GET /?access_token=foobar
--- error_code: 200
--- response_body
yay, upstream
--- no_error_log
[error]

=== TEST 12: calling /authorize with state returns same value back on redirect_uri
--- main_config
  env REDIS_HOST=$TEST_NGINX_REDIS_HOST;
--- http_config
  lua_package_path "$TEST_NGINX_LUA_PATH";

  init_by_lua_block {
    require('apicast.configuration_loader').mock({
      services = {
        { id = 42,
          backend_version = 'oauth',
          proxy = { oauth_login_url = "" } }
      }
    })
  }
--- config
  include $TEST_NGINX_APICAST_CONFIG;

  location = /fake-authorize {
    content_by_lua_block {
      local authorize = require('apicast.oauth.apicast_oauth.authorize')
      local params = authorize.extract_params()
      local nonce = authorize.persist_nonce(42, params)
      ngx.exec('/callback?redirect_uri=' .. params.redirect_uri .. '&state=' .. nonce)
    }
  }
--- request
GET /fake-authorize?client_id=id&redirect_uri=http://example.com/redirect&response_type=code&scope=whatever&state=12345
--- error_code: 302
--- response_body_like chomp
^<html>
--- response_headers_like 
Location: http://example.com/redirect\?code=\w+&state=12345
--- no_error_log
[error]

=== TEST 13: calling with correct access_token in Authorization header proxies to the api upstream
--- http_config
  lua_package_path "$TEST_NGINX_LUA_PATH";
  include $TEST_NGINX_UPSTREAM_CONFIG;

  init_by_lua_block {
    require('apicast.configuration_loader').mock({
      services = {
        {
          backend_version = 'oauth',
          proxy = {
            credentials_location = "headers",
            api_backend = "http://127.0.0.1:$TEST_NGINX_SERVER_PORT/api-backend/",
            proxy_rules = {
              { pattern = '/', http_method = 'GET', metric_system_name = 'hits', delta = 1 }
            }
          }
        }
      }
    })

    ngx.shared.api_keys:set('default:foobar:usage%5Bhits%5D=0', 200)
  }
  lua_shared_dict api_keys 1m;
--- config
  include $TEST_NGINX_APICAST_CONFIG;
  include $TEST_NGINX_BACKEND_CONFIG;

  location /api-backend/ {
    echo "yay, upstream";
  }

  location = /backend/transactions/oauth_authrep.xml {
    echo 'ok';
  }
--- request
GET /
--- more_headers
Authorization: Bearer foobar
--- error_code: 200
--- response_body
yay, upstream
--- no_error_log
[error]

=== TEST 14: calling with access_token in query when credentials location is 'headers' fails with 'auth missing'
--- http_config
  lua_package_path "$TEST_NGINX_LUA_PATH";

  init_by_lua_block {
    require('apicast.configuration_loader').mock({
      services = {
        {
          backend_version = 'oauth',
          proxy = {
            credentials_location = 'headers',
            error_auth_missing = 'credentials missing!',
            error_status_auth_missing = 401,
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
  include $TEST_NGINX_BACKEND_CONFIG;
--- request
GET /?access_token=foobar
--- error_code: 401
--- response_body chomp
credentials missing!
--- no_error_log
[error]

=== TEST 15: calling with access_token in header when the type is not 'Bearer' (case-sensitive) fails with 'auth missing'
--- http_config
  lua_package_path "$TEST_NGINX_LUA_PATH";

  init_by_lua_block {
    require('apicast.configuration_loader').mock({
      services = {
        {
          backend_version = 'oauth',
          proxy = {
            credentials_location = 'headers',
            error_auth_missing = 'credentials missing!',
            error_status_auth_missing = 401,
            proxy_rules = {
              { pattern = '/', http_method = 'GET', metric_system_name = 'hits', delta = 1}
            }
          }
        }
      }
    })
  }
  lua_shared_dict api_keys 1m;
--- config
  include $TEST_NGINX_APICAST_CONFIG;
  include $TEST_NGINX_BACKEND_CONFIG;
--- request
GET /
--- more_headers
Authorization: bearer foobar
--- error_code: 401
--- response_body chomp
credentials missing!
--- no_error_log
[error]


=== TEST 16: calling /oauth/token returns error message on empty client secret
Regression test for CVE-2017-7512
--- main_config
  env REDIS_HOST=$TEST_NGINX_REDIS_HOST;
--- http_config
  include $TEST_NGINX_UPSTREAM_CONFIG;
  lua_package_path "$TEST_NGINX_LUA_PATH";
  init_by_lua_block {
    require('apicast.configuration_loader').mock({
      services = {
        { id = 42, backend_version = 'oauth',
         backend_authentication_type = 'provider_key',
         backend_authentication_value = 'fookey', }
      }
    })
  }
--- config
  include $TEST_NGINX_APICAST_CONFIG;

  lua_need_request_body on;
  location = /t {
    content_by_lua_block {
      local authorize = require('apicast.oauth.apicast_oauth.authorize')
      local authorized_callback = require('apicast.oauth.apicast_oauth.authorized_callback')
      local redirect_uri = 'http://example.com/redirect'
      local nonce = authorize.persist_nonce(42, {
        client_id = 'foo',
        state = 'somestate',
        redirect_uri = redirect_uri,
        scope = 'plan'
      })
      local client_data = authorized_callback.retrieve_client_data(42, { state = nonce })
      local code = authorized_callback.generate_code(client_data)

      assert(authorized_callback.persist_code(client_data, { state = 'somestate', user_id = 'someuser', redirect_uri = 'redirect_uri' }, code))

      ngx.req.set_method(ngx.HTTP_POST)
      ngx.req.set_body_data('grant_type=authorization_code&client_id=client_id&redirect_uri=redirect_uri&client_secret=&code=' .. code)
      ngx.exec('/oauth/token')
    }
  }

    location = /backend/transactions/oauth_authorize.xml {
      content_by_lua_block {
        expected = "provider_key=fookey&service_id=42&app_key=&app_id=client_id&redirect_uri=redirect_uri"
        require('luassert').same(ngx.decode_args(expected), ngx.req.get_uri_args(0))
        ngx.say('<?xml version="1.0" encoding="UTF-8"?><status><authorized>true</authorized><application><key>client_secret</key></application></status>')
      }
    }

    location = /backend/services/42/oauth_access_tokens.xml {
      content_by_lua_block {
        ngx.exit(200)
      }
    }
--- request
GET /t
--- response_body chomp
{"error":"invalid_client"}
--- error_code: 401
--- no_error_log
[error]

=== TEST 17: return error status code and message when access token couldn't be stored in 3scale
--- main_config
  env REDIS_HOST=$TEST_NGINX_REDIS_HOST;
--- http_config
  include $TEST_NGINX_UPSTREAM_CONFIG;
  lua_package_path "$TEST_NGINX_LUA_PATH";
  init_by_lua_block {
    require('apicast.configuration_loader').mock({
      services = {
        { id = 42, backend_version = 'oauth',
         backend_authentication_type = 'provider_key',
         backend_authentication_value = 'fookey', }
      }
    })
  }
--- config
  include $TEST_NGINX_APICAST_CONFIG;

  lua_need_request_body on;
  location = /t {
    content_by_lua_block {
      local authorize = require('apicast.oauth.apicast_oauth.authorize')
      local authorized_callback = require('apicast.oauth.apicast_oauth.authorized_callback')
      local code = 'authcode'
      local params = { user_id = 'someuser' }
      local client_data = {
        client_id = 'foo',
        secret_id = 'bar',
        redirect_uri = 'redirect',
        access_token = 'token'
      }

      assert(authorized_callback.persist_code(client_data, params, code))

      ngx.req.set_method(ngx.HTTP_POST)
      ngx.req.set_body_data('grant_type=authorization_code&client_id=foo&client_secret=bar&redirect_uri=redirect&code=' .. code)
      ngx.exec('/oauth/token')
    }
  }

    location = /backend/transactions/oauth_authorize.xml {
      content_by_lua_block {
        expected = "provider_key=fookey&service_id=42&app_key=bar&app_id=foo&redirect_uri=redirect"
        require('luassert').same(ngx.decode_args(expected), ngx.req.get_uri_args(0))
        ngx.say('<?xml version="1.0" encoding="UTF-8"?><status><authorized>true</authorized><application><key>bar</key></application></status>')
      }
    }

    location = /backend/services/42/oauth_access_tokens.xml {
      content_by_lua_block {
        ngx.status = 400
        ngx.print("token couldn't be stored")
        ngx.exit(400)
      }
    }

--- request
GET /t
--- error_code: 400
--- response_body
{"error":"token couldn't be stored"}
--- no_error_log
[error]

=== TEST 18: when calling /oauth/token request headers are not passed to the backend
--- main_config
  env REDIS_HOST=$TEST_NGINX_REDIS_HOST;
  env APICAST_OAUTH_TOKENS_TTL=123;
--- http_config
  include $TEST_NGINX_UPSTREAM_CONFIG;
  lua_package_path "$TEST_NGINX_LUA_PATH";
  init_by_lua_block {
    require('apicast.configuration_loader').mock({
      services = {
        { id = 42, backend_version = 'oauth',
         backend_authentication_type = 'provider_key',
         backend_authentication_value = 'fookey', }
      }
    })
  }
--- config
  include $TEST_NGINX_APICAST_CONFIG;

  lua_need_request_body on;
  location = /t {
    content_by_lua_block {
      local authorized_callback = require('apicast.oauth.apicast_oauth.authorized_callback')
      local code = 'authcode'
      local params = { user_id = 'someuser' }
      local client_data = {
        client_id = 'foo',
        secret_id = 'bar',
        redirect_uri = 'redirect',
        access_token = 'token'
      }

      assert(authorized_callback.persist_code(client_data, params, code))

      ngx.req.set_method(ngx.HTTP_POST)
      ngx.req.set_body_data('grant_type=authorization_code&client_id=foo&client_secret=bar&redirect_uri=redirect&code=' .. code)
      ngx.exec('/oauth/token')
    }
  }

    location = /backend/transactions/oauth_authorize.xml {
      content_by_lua_block {
        expected = "provider_key=fookey&service_id=42&app_key=bar&app_id=foo&redirect_uri=redirect"
        require('luassert').same(ngx.decode_args(expected), ngx.req.get_uri_args(0))
        ngx.say('<?xml version="1.0" encoding="UTF-8"?><status><authorized>true</authorized><application><key>bar</key></application></status>')
      }
    }

    location = /backend/services/42/oauth_access_tokens.xml {
      content_by_lua_block {
        local ttl = tonumber(ngx.req.get_post_args()['ttl'])
        if ttl ~= 123 then
          ngx.log(ngx.ERR, 'Backend did not receive the correct TTL.')
          ngx.exit(400)
        end

        if ngx.var.http_content_type then
          ngx.log(ngx.ERR, 'Invalid Content-Type: ', ngx.var.http_content_type)
          ngx.status = 400
          ngx.print('invalid content-type')
        end
      }
    }

--- request
GET /t
--- more_headers
Content-Type: application/json
--- error_code: 200
--- response_body
{"token_type":"bearer","expires_in":123,"access_token":"token"}
--- no_error_log
[error]

=== TEST 19: default token TTL when not specified
When a token TTL is not specified, it applies a default of 7 days (604800 s)
--- main_config
  env REDIS_HOST=$TEST_NGINX_REDIS_HOST;
--- http_config
  include $TEST_NGINX_UPSTREAM_CONFIG;
  lua_package_path "$TEST_NGINX_LUA_PATH";
  init_by_lua_block {
    require('apicast.configuration_loader').mock({
      services = {
        { id = 42, backend_version = 'oauth',
         backend_authentication_type = 'provider_key',
         backend_authentication_value = 'fookey', }
      }
    })
  }
--- config
  include $TEST_NGINX_APICAST_CONFIG;

  lua_need_request_body on;
  location = /t {
    content_by_lua_block {
      local authorized_callback = require('apicast.oauth.apicast_oauth.authorized_callback')
      local code = 'authcode'
      local params = { user_id = 'someuser' }
      local client_data = {
        client_id = 'foo',
        secret_id = 'bar',
        redirect_uri = 'redirect',
        access_token = 'token'
      }

      assert(authorized_callback.persist_code(client_data, params, code))

      ngx.req.set_method(ngx.HTTP_POST)
      ngx.req.set_body_data('grant_type=authorization_code&client_id=foo&client_secret=bar&redirect_uri=redirect&code=' .. code)
      ngx.exec('/oauth/token')
    }
  }

  set $backend_host '127.0.0.1';
  set $service_id 42;
  set $backend_authentication_type 'provider_key';
  set $backend_authentication_value 'fookey';

  location = /backend/transactions/oauth_authorize.xml {
    content_by_lua_block {
      expected = "provider_key=fookey&service_id=42&app_key=bar&app_id=foo&redirect_uri=redirect"
      require('luassert').same(ngx.decode_args(expected), ngx.req.get_uri_args(0))
      require('luassert').same(ngx.var.backend_host, ngx.var.host)
      ngx.say('<?xml version="1.0" encoding="UTF-8"?><status><authorized>true</authorized><application><key>bar</key></application></status>')
    }
  }

  location = /backend/services/42/oauth_access_tokens.xml {
    content_by_lua_block {
      local ttl = tonumber(ngx.req.get_post_args()['ttl'])
      if ttl ~= 604800 then
        ngx.log(ngx.ERR, 'Backend did not receive the correct TTL.')
        ngx.exit(400)
      else
        ngx.exit(200)
      end
    }
  }

--- request
GET /t
--- more_headers
Content-Type: application/json
--- error_code: 200
--- response_body
{"token_type":"bearer","expires_in":604800,"access_token":"token"}
--- no_error_log
[error]

=== TEST 20: default token TTL when given an empty one
When an empty token TTL is received, Apicast applies a default of 7 days (604800 s)
--- main_config
  env REDIS_HOST=$TEST_NGINX_REDIS_HOST;
  env APICAST_OAUTH_TOKENS_TTL=;
--- http_config
  include $TEST_NGINX_UPSTREAM_CONFIG;
  lua_package_path "$TEST_NGINX_LUA_PATH";
  init_by_lua_block {
    require('apicast.configuration_loader').mock({
      services = {
        { id = 42, backend_version = 'oauth',
         backend_authentication_type = 'provider_key',
         backend_authentication_value = 'fookey', }
      }
    })
  }
--- config
  include $TEST_NGINX_APICAST_CONFIG;

  lua_need_request_body on;
  location = /t {
    content_by_lua_block {
      local authorized_callback = require('apicast.oauth.apicast_oauth.authorized_callback')
      local code = 'authcode'
      local params = { user_id = 'someuser' }
      local client_data = {
        client_id = 'foo',
        secret_id = 'bar',
        redirect_uri = 'redirect',
        access_token = 'token'
      }

      assert(authorized_callback.persist_code(client_data, params, code))

      ngx.req.set_method(ngx.HTTP_POST)
      ngx.req.set_body_data('grant_type=authorization_code&client_id=foo&client_secret=bar&redirect_uri=redirect&code=' .. code)
      ngx.exec('/oauth/token')
    }
  }

  set $backend_host '127.0.0.1';
  set $service_id 42;
  set $backend_authentication_type 'provider_key';
  set $backend_authentication_value 'fookey';

  location = /backend/transactions/oauth_authorize.xml {
    content_by_lua_block {
      expected = "provider_key=fookey&service_id=42&app_key=bar&app_id=foo&redirect_uri=redirect"
      require('luassert').same(ngx.decode_args(expected), ngx.req.get_uri_args(0))
      require('luassert').same(ngx.var.backend_host, ngx.var.host)
      ngx.say('<?xml version="1.0" encoding="UTF-8"?><status><authorized>true</authorized><application><key>bar</key></application></status>')
    }
  }

  location = /backend/services/42/oauth_access_tokens.xml {
    content_by_lua_block {
      local ttl = tonumber(ngx.req.get_post_args()['ttl'])
      if ttl ~= 604800 then
        ngx.log(ngx.ERR, 'Backend did not receive the correct TTL.')
        ngx.exit(400)
      else
        ngx.exit(200)
      end
    }
  }

--- request
GET /t
--- more_headers
Content-Type: application/json
--- error_code: 200
--- response_body
{"token_type":"bearer","expires_in":604800,"access_token":"token"}
--- no_error_log
[error]

=== TEST 21: correct 3scale backend options when using oauth native
When authorizing against 3scale's backend, the call includes the correct
options in the headers. That is, it includes the 'rejection_reason' option,
but not the 'no_body' one, as in the native oauth flow, parsing the response
body is necessary.
--- http_config
  lua_package_path "$TEST_NGINX_LUA_PATH";
  include $TEST_NGINX_UPSTREAM_CONFIG;

  init_by_lua_block {
    require('apicast.configuration_loader').mock({
      services = {
        {
          backend_version = 'oauth',
          proxy = {
            credentials_location = "query",
            api_backend = "http://127.0.0.1:$TEST_NGINX_SERVER_PORT/api-backend/",
            proxy_rules = {
              { pattern = '/', http_method = 'GET', metric_system_name = 'hits', delta = 1 }
            }
          }
        }
      }
    })

    ngx.shared.api_keys:set('default:foobar:usage%5Bhits%5D=0', 200)
  }
  lua_shared_dict api_keys 1m;
--- config
  include $TEST_NGINX_APICAST_CONFIG;
  include $TEST_NGINX_BACKEND_CONFIG;

  location /api-backend/ {
    echo "yay, upstream";
  }

  location = /backend/transactions/oauth_authrep.xml {
    content_by_lua_block {
      require('luassert').same(
        ngx.var['http_3scale_options'],
        'rejection_reason_header=1&limit_headers=1'
      )
    }
  }
--- request
GET /?access_token=foobar
--- error_code: 200
--- response_body
yay, upstream
--- no_error_log
[error]
