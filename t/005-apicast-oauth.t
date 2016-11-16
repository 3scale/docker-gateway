use Test::Nginx::Socket::Lua 'no_plan';
use Cwd qw(cwd);

my $pwd = cwd();
my $apicast = $ENV{TEST_NGINX_APICAST_PATH} || "$pwd/apicast";

$ENV{TEST_NGINX_LUA_PATH} = "$apicast/src/?.lua;;";
$ENV{TEST_NGINX_BACKEND_CONFIG} = "$apicast/conf.d/backend.conf";
$ENV{TEST_NGINX_UPSTREAM_CONFIG} = "$apicast/http.d/upstream.conf";
$ENV{TEST_NGINX_APICAST_CONFIG} = "$apicast/conf.d/apicast.conf";

$ENV{TEST_NGINX_REDIS_HOST} ||= $ENV{REDIS_HOST} || "127.0.0.1";
$ENV{TEST_NGINX_RESOLVER} ||= `grep nameserver /etc/resolv.conf | awk '{print \$2}' | tr '\n' ' '`;

log_level('debug');
repeat_each(2);
no_root_location();
run_tests();

__DATA__

=== TEST 1: calling /authorize redirects with error when credentials are missing
--- http_config
  lua_package_path "$TEST_NGINX_LUA_PATH";

  init_by_lua_block {
    require('configuration').save({
      services = {
        { backend_version = 'oauth',
          proxy = { oauth_login_url = "http://example.com/redirect" } }
      }
    })
  }
--- config
  include $TEST_NGINX_APICAST_CONFIG;
--- request
GET /authorize
--- error_code: 302
--- response_headers
Location: http://example.com/redirect?error=invalid_client


=== TEST 2: calling /authorize works (Authorization Code)
[Section 1.3.1 of RFC 6749](https://tools.ietf.org/html/rfc6749#section-1.3.1)
--- main_config
  env REDIS_HOST=$TEST_NGINX_REDIS_HOST;
--- http_config
  resolver $TEST_NGINX_RESOLVER;
  lua_package_path "$TEST_NGINX_LUA_PATH";

  init_by_lua_block {
    require('configuration').save({
      services = {
        { backend_version = 'oauth',
          proxy = { oauth_login_url = "http://example.com/redirect" } }
      }
    })
  }
--- config
  include $TEST_NGINX_APICAST_CONFIG;

  set $backend_endpoint 'http://127.0.0.1:$TEST_NGINX_SERVER_PORT/backend';
  set $service_id 42;
  set $backend_authentication_type 'provider_key';
  set $backend_authentication_value 'fookey';

  location = /backend/transactions/oauth_authorize.xml {
    content_by_lua_block {
      expected = "provider_key=fookey&service_id=42&redirect_uri=otheruri&app_id=id"
      if ngx.var.args == expected then
        ngx.exit(200)
      else
        ngx.exit(403)
      end
    }
  }
--- request
GET /authorize?client_id=id&redirect_uri=otheruri&response_type=code&scope=whatever
--- error_code: 302
--- response_headers_like
Location: http://example.com/redirect\?scope=whatever&response_type=code&state=\w+&tok=\w+&redirect_uri=otheruri&client_id=id
--- no_error_log
[error]



=== TEST 3: calling /authorize works (Implicit)
[Section 1.3.2 of RFC 6749](https://tools.ietf.org/html/rfc6749#section-1.3.2)
--- http_config
  lua_package_path "$TEST_NGINX_LUA_PATH";

  init_by_lua_block {
    require('configuration').save({
      services = {
        {
         id = 42, backend_version = 'oauth',
         proxy = { oauth_login_url = "http://example.com/redirect" }
        }
      }
    })
  }
--- config
  include $TEST_NGINX_APICAST_CONFIG;

  set $backend_endpoint 'http://127.0.0.1:$TEST_NGINX_SERVER_PORT/backend';
  set $backend_authentication_type 'provider_key';
  set $backend_authentication_value 'fookey';

  location = /backend/transactions/oauth_authorize.xml {
    content_by_lua_block {
      if ngx.var.args == "provider_key=fookey&service_id=42&redirect_uri=otheruri&app_id=id" then
        ngx.exit(200)
      else
        ngx.exit(403)
      end
    }
  }
--- request
GET /authorize?client_id=id&redirect_uri=otheruri&response_type=token&scope=whatever
--- error_code: 302
--- response_headers_like
Location: http://example.com/redirect\?scope=whatever&response_type=token&error=unsupported_response_type&redirect_uri=otheruri&client_id=id
--- no_error_log
[error]

=== TEST 4: calling /oauth/token returns correct error message on missing parameters
--- http_config
  lua_package_path "$TEST_NGINX_LUA_PATH";
  init_by_lua_block {
    require('configuration').save({
      services = {
        { backend_version = 'oauth' }
      }
    })
  }
--- config
include $TEST_NGINX_APICAST_CONFIG;
--- request
POST /oauth/token
--- response_body chomp
{"error":"invalid_client"}
--- error_code: 401

=== TEST 5: calling /oauth/token returns correct error message on invalid parameters
--- http_config
  lua_package_path "$TEST_NGINX_LUA_PATH";
  init_by_lua_block {
    require('configuration').save({
      services = {
        { backend_version = 'oauth' }
      }
    })
  }
--- config
include $TEST_NGINX_APICAST_CONFIG;
--- request
POST /oauth/token?grant_type=authorization_code&client_id=client_id&redirect_uri=redirect_uri&client_secret=client_secret&code=code
--- response_body chomp
{"error":"invalid_client"}
--- error_code: 401

=== TEST 6: calling /callback without params returns correct erro message
--- http_config
  lua_package_path "$TEST_NGINX_LUA_PATH";
  init_by_lua_block {
    require('configuration').save({
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

=== TEST 7: calling /callback redirects to correct error when state is missing
--- http_config
  lua_package_path "$TEST_NGINX_LUA_PATH";
  init_by_lua_block {
    require('configuration').save({
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

=== TEST 8: calling /callback redirects to correct error when state is missing
--- main_config
  env REDIS_HOST=$TEST_NGINX_REDIS_HOST;
--- http_config
  resolver $TEST_NGINX_RESOLVER;
  lua_package_path "$TEST_NGINX_LUA_PATH";
  init_by_lua_block {
    require('configuration').save({
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

=== TEST 9: calling /callback works
Not part of the RFC. This is the Gateway API to create access tokens and redirect back to the Client.
--- main_config
  env REDIS_HOST=$TEST_NGINX_REDIS_HOST;
--- http_config
  resolver $TEST_NGINX_RESOLVER;
  lua_package_path "$TEST_NGINX_LUA_PATH";
  init_by_lua_block {
    require('configuration').save({
      services = {
        { id = 42, backend_version = 'oauth', oauth_login_url = "" }
      }
    })
  }
--- config
  include $TEST_NGINX_APICAST_CONFIG;

  location = /fake-authorize {
    content_by_lua_block {
      local authorize = require('authorize')
      local redirect_uri = 'http://example.com/redirect'
      local nonce = authorize.persist_nonce(42, {
        client_id = 'foo',
        state = 'somestate',
        redirect_uri = redirect_uri,
        scope = 'plan'
      })
      ngx.exec('/callback?redirect_uri=' .. redirect_uri .. '&state=' .. nonce)
    }
  }
--- request
GET /fake-authorize
--- error_code: 302
--- response_body_like chomp
^<html>
--- response_headers_like
Location: http://example.com/redirect\?code=\w+&state=\w+

=== TEST 10: calling /oauth/token returns correct error message on invalid parameters
--- main_config
  env REDIS_HOST=$TEST_NGINX_REDIS_HOST;
--- http_config
  resolver $TEST_NGINX_RESOLVER;
  lua_package_path "$TEST_NGINX_LUA_PATH";
  init_by_lua_block {
    require('configuration').save({
      services = {
        { id = 42, backend_version = 'oauth' }
      }
    })
  }
--- config
  include $TEST_NGINX_APICAST_CONFIG;

  lua_need_request_body on;
  location = /t {
    content_by_lua_block {
      local authorize = require('authorize')
      local authorized_callback = require('authorized_callback')
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
      ngx.req.set_body_data('grant_type=authorization_code&client_id=client_id&redirect_uri=redirect_uri&client_secret=client_secret&code=' .. code)
      ngx.exec('/oauth/token')
    }
  }

  set $backend_endpoint 'http://127.0.0.1:$TEST_NGINX_SERVER_PORT/backend';
    set $backend_authentication_type 'provider_key';
    set $backend_authentication_value 'fookey';

    location = /backend/transactions/oauth_authorize.xml {
      content_by_lua_block {
        expected = "provider_key=fookey&service_id=42&app_key=client_secret&redirect_uri=redirect_uri&app_id=client_id"
        if ngx.var.args == expected then
          ngx.exit(200)
        else
          ngx.log(ngx.ERR, 'expected: ' .. expected .. ' got: ' .. ngx.var.args)
          ngx.exit(403)
        end
      }
    }

    location = /backend/services/42/oauth_access_tokens.xml {
      content_by_lua_block {
        ngx.exit(200)
      }
    }
--- request
GET /t
--- response_body_like
{"token_type":"bearer","expires_in":604800,"access_token":"\w+"}
--- error_code: 200


=== TEST 1: calling with correct access_token proxies to the api upstream
--- http_config
  lua_package_path "$TEST_NGINX_LUA_PATH";
  include $TEST_NGINX_UPSTREAM_CONFIG;

  init_by_lua_block {
    require('configuration').save({
      services = {
        {
          backend_version = 'oauth',
          proxy = {
          api_backend = "http://127.0.0.1:$TEST_NGINX_SERVER_PORT/api-backend/",
            proxy_rules = {
              { pattern = '/', http_method = 'GET', metric_system_name = 'hits' }
            }
          }
        }
      }
    })

    ngx.shared.api_keys:set('default:foobar:usage[hits]=0', 200)
  }
  lua_shared_dict api_keys 1m;
--- config
  include $TEST_NGINX_APICAST_CONFIG;
  include $TEST_NGINX_BACKEND_CONFIG;

  location /api-backend/ {
    echo "yay, upstream";
  }
--- request
GET /?access_token=foobar
--- error_code: 200
--- response_body
yay, upstream
