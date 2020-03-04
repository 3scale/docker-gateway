use lib 't';

use Test::APIcast::Blackbox 'no_plan';


# Enable master process to be able to make http2 request if not lua-http will
# not work0
$Test::Nginx::Util::MasterProcessEnabled = "on";

add_block_preprocessor(sub {
    my $block = shift;
    my $custom_config = $block->custom_config;
    my $sites_d = $block->sites_d || '';


    if (defined $custom_config) {

      $sites_d .= <<_EOC_;
        $custom_config
_EOC_

      $block->set_value('sites_d', $sites_d)
    }
});

# Load lua helpers to make calls faster
use Cwd qw(getcwd abs_path);
my $cwd = getcwd();
$ENV{LUA_PATH} = "$ENV{LUA_PATH};$cwd/t/helpers/?.lua";

$ENV{APICAST_HTTPS_RANDOM_PORT} = Test::APIcast::get_random_port();

repeat_each(2);
run_tests();

__DATA__

=== TEST 1: Simple HTTP2 request termination.
This test enables HTTP2 termination on endpoint and proxy it to a api_backend
that is not https or HTTP2 enabled.
--- env eval
(
    'APICAST_HTTPS_PORT' => $ENV{APICAST_HTTPS_RANDOM_PORT},
    'APICAST_SSL_CERT_FILE_CA' => "$Test::Nginx::Util::ServRoot/html/ca.crt",
    'APICAST_HTTPS_CERTIFICATE' => "$Test::Nginx::Util::ServRoot/html/server.crt",
    'APICAST_HTTPS_CERTIFICATE_KEY' => "$Test::Nginx::Util::ServRoot/html/server.key",
)
--- backend
  location /transactions/authrep.xml {
    content_by_lua_block {
      ngx.exit(200)
    }
  }
--- configuration
{
  "services": [
    {
      "id": 42,
      "backend_version": 1,
      "backend_authentication_type": "service_token",
      "backend_authentication_value": "token-value",
      "proxy": {
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/",
        "policy_chain": [
          {
            "name": "apicast.policy.apicast"
          }
        ],
        "proxy_rules": [
          {
            "pattern": "/",
            "http_method": "GET",
            "metric_system_name": "hits",
            "delta": 1
          }
        ]
      }
    }
  ]
}
--- upstream
  location / {
    content_by_lua_block {
      ngx.say('yay, api backend');
    }
  }
--- test
content_by_lua_block {
  local request = require("request")
  local resty_env = require 'resty.env'

  local https_port = resty_env.get('APICAST_HTTPS_PORT')
  local uri = "https://localhost:".. https_port .."/?user_key=foo"
  local req = request.request(uri, "get", "./t/fixtures/CA/ca-bundle.crt")
  assert(req, "Request failed")
  req:expect200()
  req:expectHTTP2()
  req:expectBody('yay, api backend\n')
}
--- user_files fixture=CA/files.pl eval
--- no_error_log
[error]

=== TEST 2: Full HTTP2 request flow
This test validates that a request that it's HTTP2 with and API-endpoint HTTP2
will use HTTP2 also.
--- init eval
$Test::Nginx::Util::SSL_PORT = Test::APIcast::get_random_port();
$Test::Nginx::Util::ENDPOINT_SSL_PORT = Test::APIcast::get_random_port();
--- env eval
(
    'APICAST_HTTPS_PORT' => $Test::Nginx::Util::SSL_PORT,
    'APICAST_SSL_CERT_FILE_CA' => "$Test::Nginx::Util::ServRoot/html/ca.crt",
    'APICAST_HTTPS_CERTIFICATE' => "$Test::Nginx::Util::ServRoot/html/server.crt",
    'APICAST_HTTPS_CERTIFICATE_KEY' => "$Test::Nginx::Util::ServRoot/html/server.key",
)
--- backend
  location /transactions/authrep.xml {
    content_by_lua_block {
      ngx.exit(200)
    }
  }
--- configuration env eval
<<EOF
{
  "services": [
    {
      "id": 42,
      "backend_version": 1,
      "backend_authentication_type": "service_token",
      "backend_authentication_value": "token-value",
      "proxy": {
        "api_backend": "https://127.0.0.1:$Test::Nginx::Util::ENDPOINT_SSL_PORT/",
        "policy_chain": [
          {
            "name": "apicast.policy.grpc"
          },
          {
            "name": "apicast.policy.apicast"
          }
        ],
        "proxy_rules": [
          {
            "pattern": "/",
            "http_method": "GET",
            "metric_system_name": "hits",
            "delta": 1
          }
        ]
      }
    }
  ]
}
EOF
--- custom_config eval
<<EOF
server {
  listen $Test::Nginx::Util::ENDPOINT_SSL_PORT ssl http2;
  ssl_certificate $Test::Nginx::Util::ServRoot/html/server.crt;
  ssl_certificate_key $Test::Nginx::Util::ServRoot/html/server.key;

  server_name _ default_server;

  location / {
    content_by_lua_block {
      ngx.say('PROTOCOL::', ngx.var.server_protocol);
    }
  }
}
EOF
--- test
content_by_lua_block {
  local request = require("request")
  local resty_env = require 'resty.env'

  local https_port = resty_env.get('APICAST_HTTPS_PORT')
  local uri = "https://localhost:".. https_port .."/?user_key=foo"
  local req = request.request(uri, "get", "./t/fixtures/CA/ca-bundle.crt")
  assert(req, "Request failed")
  req:expect200()
  req:expectHTTP2()
  req:expectBody('PROTOCOL::HTTP/2.0\n')
}
--- curl
--- user_files fixture=CA/files.pl eval
--- no_error_log
[error]


=== TEST 3: Full HTTP2 with MTLS
Full HTTP2 connection using mutual TLS connection from APICast to Endpoint.
--- init eval
$Test::Nginx::Util::SSL_PORT = Test::APIcast::get_random_port();
$Test::Nginx::Util::ENDPOINT_SSL_PORT = Test::APIcast::get_random_port();
--- env eval
(
  'APICAST_PROXY_HTTPS_CERTIFICATE' => "$Test::Nginx::Util::ServRoot/html/client.crt",
  'APICAST_PROXY_HTTPS_CERTIFICATE_KEY' => "$Test::Nginx::Util::ServRoot/html/client.key",
  'APICAST_PROXY_HTTPS_PASSWORD_FILE' => "$Test::Nginx::Util::ServRoot/html/passwords.file",
  'APICAST_PROXY_HTTPS_SESSION_REUSE' => 'on',
)
--- backend
  location /transactions/authrep.xml {
    content_by_lua_block {
      ngx.exit(200)
    }
  }
--- configuration env eval
<<EOF
{
  "services": [
    {
      "id": 42,
      "backend_version": 1,
      "backend_authentication_type": "service_token",
      "backend_authentication_value": "token-value",
      "proxy": {
        "api_backend": "https://127.0.0.1:$Test::Nginx::Util::ENDPOINT_SSL_PORT/",
        "policy_chain": [
          {
            "name": "apicast.policy.grpc"
          },
          {
            "name": "apicast.policy.apicast"
          }
        ],
        "proxy_rules": [
          {
            "pattern": "/",
            "http_method": "GET",
            "metric_system_name": "hits",
            "delta": 1
          }
        ]
      }
    }
  ]
}
EOF
--- custom_config eval
<<EOF
server {
  listen $Test::Nginx::Util::ENDPOINT_SSL_PORT ssl http2;

  ssl_certificate $Test::Nginx::Util::ServRoot/html/server.crt;
  ssl_certificate_key $Test::Nginx::Util::ServRoot/html/server.key;

  ssl_client_certificate $Test::Nginx::Util::ServRoot/html/client.crt;
  ssl_verify_client on;

  server_name _ default_server;

  location / {
    echo 'ssl_client_s_dn: \$ssl_client_s_dn';
    echo 'ssl_client_i_dn: \$ssl_client_i_dn';
  }
}
EOF
--- test
content_by_lua_block {
  local request = require("request")
  local resty_env = require 'resty.env'

  local uri = "http://localhost:".. ngx.var.apicast_port .."/?user_key=foo"
  local req = request.request(uri, "get")
  assert(req, "Request failed")
  req:expect200()
  req:expectBody(
    'ssl_client_s_dn: CN=localhost,OU=APIcast,O=3scale\n' ..
    'ssl_client_i_dn: CN=localhost,OU=APIcast,O=3scale\n'
  )
}
--- curl
--- user_files fixture=mutual_ssl.pl eval
--- no_error_log
[error]


=== TEST 4: Full HTTP2 with headers modification
Full HTTP2 connection using headers policy to validate that works correctly
--- init eval
$Test::Nginx::Util::SSL_PORT = Test::APIcast::get_random_port();
$Test::Nginx::Util::ENDPOINT_SSL_PORT = Test::APIcast::get_random_port();
--- env eval
(
    'APICAST_HTTPS_PORT' => $Test::Nginx::Util::SSL_PORT,
    'APICAST_SSL_CERT_FILE_CA' => "$Test::Nginx::Util::ServRoot/html/ca.crt",
    'APICAST_HTTPS_CERTIFICATE' => "$Test::Nginx::Util::ServRoot/html/server.crt",
    'APICAST_HTTPS_CERTIFICATE_KEY' => "$Test::Nginx::Util::ServRoot/html/server.key",
)
--- backend
  location /transactions/authrep.xml {
    content_by_lua_block {
      ngx.exit(200)
    }
  }
--- configuration env eval
<<EOF
{
  "services": [
    {
      "id": 42,
      "backend_version": 1,
      "backend_authentication_type": "service_token",
      "backend_authentication_value": "token-value",
      "proxy": {
        "api_backend": "https://127.0.0.1:$Test::Nginx::Util::ENDPOINT_SSL_PORT/",
        "policy_chain": [
          {
            "name": "apicast.policy.headers",
            "configuration":
              {
                "request":
                  [
                    { "op": "set", "header": "New-Header", "value": "new" },
                    { "op": "set", "header": "bar", "value": "updated" },
                    { "op": "delete", "header": "test" }
                  ]
              }
          },
          {
            "name": "apicast.policy.grpc"
          },
          {
            "name": "apicast.policy.apicast"
          }
        ],
        "proxy_rules": [
          {
            "pattern": "/",
            "http_method": "GET",
            "metric_system_name": "hits",
            "delta": 1
          }
        ]
      }
    }
  ]
}
EOF
--- custom_config eval
<<EOF
server {
  listen $Test::Nginx::Util::ENDPOINT_SSL_PORT ssl http2;
  ssl_certificate $Test::Nginx::Util::ServRoot/html/server.crt;
  ssl_certificate_key $Test::Nginx::Util::ServRoot/html/server.key;

  server_name _ default_server;

  location / {
    content_by_lua_block {
      local assert = require('luassert')
      assert.same('new', ngx.req.get_headers()['New-Header'])
      assert.same('foobar', ngx.req.get_headers()['foo'])
      assert.same('updated', ngx.req.get_headers()['bar'])
      assert.falsy(ngx.req.get_headers()['test'])
    }
  }
}
EOF
--- test
content_by_lua_block {
  local request = require("request")
  local resty_env = require 'resty.env'

  local https_port = resty_env.get('APICAST_HTTPS_PORT')
  local uri = "https://localhost:".. https_port .."/?user_key=foo"
  local req = request.request(
    uri, "get", "./t/fixtures/CA/ca-bundle.crt", nil,
    { foo="foobar", bar="foobar", test="test" })
  assert(req, "Request failed")
  req:expect200()
  req:expectHTTP2()
}
--- user_files fixture=CA/files.pl eval
--- no_error_log
[error]
