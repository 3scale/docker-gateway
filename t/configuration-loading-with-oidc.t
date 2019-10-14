use lib 't';
use Test::APIcast::Blackbox 'no_plan';


run_tests();

__DATA__

=== TEST 1: load a config where only some of the services have an OIDC configuration
This is a regression test. APIcast crashed when loading a config where only
some of the services used OIDC.
The reason is that we created an array of OIDC configs with
size=number_of_services. Let's say we have 100 services and only the 50th has an
OIDC config. In this case, we created this Lua table:
{ [50] = oidc_config_here }.
The problem is that cjson raises an error when trying to convert a sparse array
like that into JSON. Using the default cjson configuration, the minimum number
of elements to reproduce the error is 11. So in this test, we create 11 services
and assign an OIDC config only to the last one. Check
https://www.kyne.com.au/~mark/software/lua-cjson-manual.html#encode_sparse_array
for more details.
Now we assign to _false_ the elements of the array that do not have an OIDC
config, so this test should not crash.
--- env eval
(
  'APICAST_CONFIGURATION_LOADER' => 'lazy',
  'THREESCALE_PORTAL_ENDPOINT' => "http://test:$ENV{TEST_NGINX_SERVER_PORT}"
)
--- upstream env
location = /admin/api/services.json {
    echo '
    {
      "services":[
        { "service": { "id":1 } },
        { "service": { "id":2 } },
        { "service": { "id":3 } },
        { "service": { "id":4 } },
        { "service": { "id":5 } },
        { "service": { "id":6 } },
        { "service": { "id":7 } },
        { "service": { "id":8 } },
        { "service": { "id":9 } },
        { "service": { "id":10 } },
        { "service": { "id":11 } }
      ]
    }';
}

location = /issuer/endpoint/.well-known/openid-configuration {
  content_by_lua_block {
    local base = "http://" .. ngx.var.host .. ':' .. ngx.var.server_port
    ngx.header.content_type = 'application/json;charset=utf-8'
    ngx.say(require('cjson').encode {
        issuer = 'https://example.com/auth/realms/apicast',
        id_token_signing_alg_values_supported = { 'RS256' },
        jwks_uri = base .. '/jwks',
    })
  }
}

location = /jwks {
  content_by_lua_block {
    ngx.header.content_type = 'application/json;charset=utf-8'
    ngx.say([[
        { "keys": [
            { "kty":"RSA","kid":"somekid",
              "n":"sKXP3pwND3rkQ1gx9nMb4By7bmWnHYo2kAAsFD5xq0IDn26zv64tjmuNBHpI6BmkLPk8mIo0B1E8MkxdKZeozQ","e":"AQAB" }
        ] }
    ]])
  }
}

location ~ /admin/api/services/([0-9]|10)/proxy/configs/production/latest.json {
echo '
{
  "proxy_config": {
    "content": {
      "id": 1,
      "backend_version": 1,
      "proxy": {
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/api/",
        "backend": {
          "endpoint": "http://test:$TEST_NGINX_SERVER_PORT"
        },
        "proxy_rules": [
          {
            "pattern": "/",
            "http_method": "GET",
            "metric_system_name": "test",
            "delta": 1
          }
        ]
      }
    }
  }
}
';
}

location = /admin/api/services/11/proxy/configs/production/latest.json {
echo '{ "proxy_config": { "content": { "proxy": { "oidc_issuer_endpoint": "http://test:$TEST_NGINX_SERVER_PORT/issuer/endpoint" } } } }';
}

location /transactions/authrep.xml {
  content_by_lua_block {
    ngx.exit(200)
  }
}

location /api/ {
  echo 'yay, api backend';
}
--- request
GET /?user_key=uk
--- error_code: 200
--- response_body
yay, api backend

=== TEST 2: load a config where only some of the services have an OIDC configuration (with a portal endpoint with path)
This test is almost the same as the previous one. The only difference is that,
in this one, THREESCALE_PORTAL_ENDPOINT has a path.
--- env eval
(
  'APICAST_CONFIGURATION_LOADER' => 'lazy',
  'THREESCALE_PORTAL_ENDPOINT' => "http://test:$ENV{TEST_NGINX_SERVER_PORT}/config"
)
--- upstream env
location = /config/production.json {
echo '
{
  "proxy_configs": [
    {
      "proxy_config": {
        "id": 1,
        "content": {
          "backend_version": 1,
          "environment": "production",
          "proxy": {
            "hosts": [
              "localhost"
            ],
            "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/api/",
            "backend": {
              "endpoint": "http://test:$TEST_NGINX_SERVER_PORT"
            },
            "proxy_rules": [
              { "pattern": "/", "http_method": "GET", "metric_system_name": "test", "delta": 1}
            ]
          }
        }
      }
    },
    { "proxy_config": { "content": {} } },
    { "proxy_config": { "content": {} } },
    { "proxy_config": { "content": {} } },
    { "proxy_config": { "content": {} } },
    { "proxy_config": { "content": {} } },
    { "proxy_config": { "content": {} } },
    { "proxy_config": { "content": {} } },
    { "proxy_config": { "content": {} } },
    { "proxy_config": { "content": {} } },
    {
      "proxy_config": {
        "id": 2,
        "content": {
          "backend_version": "oidc",
          "environment": "production",
          "proxy": {
            "oidc_issuer_endpoint": "http://test:$TEST_NGINX_SERVER_PORT/issuer/endpoint",
            "backend": {
              "endpoint": "http://test:$TEST_NGINX_SERVER_PORT"
            },
            "proxy_rules": [
              { "pattern": "/", "http_method": "GET", "metric_system_name": "test", "delta": 1}
            ]
          }
        }
      }
    }
  ]
}
';
}

location = /issuer/endpoint/.well-known/openid-configuration {
  content_by_lua_block {
    local base = "http://" .. ngx.var.host .. ':' .. ngx.var.server_port
    ngx.header.content_type = 'application/json;charset=utf-8'
    ngx.say(require('cjson').encode {
        issuer = 'https://example.com/auth/realms/apicast',
        id_token_signing_alg_values_supported = { 'RS256' },
        jwks_uri = base .. '/jwks',
    })
  }
}

location = /jwks {
  content_by_lua_block {
    ngx.header.content_type = 'application/json;charset=utf-8'
    ngx.say([[
        { "keys": [
            { "kty":"RSA","kid":"somekid",
              "n":"sKXP3pwND3rkQ1gx9nMb4By7bmWnHYo2kAAsFD5xq0IDn26zv64tjmuNBHpI6BmkLPk8mIo0B1E8MkxdKZeozQ","e":"AQAB" }
        ] }
    ]])
  }
}

location /transactions/authrep.xml {
  content_by_lua_block {
    ngx.exit(200)
  }
}

location /api/ {
  echo 'yay, api backend';
}
--- request
GET /?user_key=uk
--- error_code: 200
--- response_body
yay, api backend
