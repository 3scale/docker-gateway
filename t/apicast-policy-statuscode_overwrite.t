use lib 't';
use Test::APIcast::Blackbox 'no_plan';

run_tests();

__DATA__

=== TEST 1: HTTP CODES policy placed before apicast
--- configuration
{
  "services": [
    {
      "id": 42,
      "backend_version":  1,
      "backend_authentication_type": "service_token",
      "backend_authentication_value": "token-value",
      "proxy": {
        "policy_chain": [
          {
            "name": "statuscode_overwrite",
            "version": "builtin",
            "configuration": {
              "http_statuses": [
                {
                  "upstream": 200,
                  "apicast": 201
                },
                {
                  "upstream": 403,
                  "apicast": 401
                }
              ]
            }
          },
          {
            "name": "apicast.policy.apicast"
          }
        ],
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/",
        "proxy_rules": [
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 1 }
        ]
      }
    }
  ]
}
--- backend
  location /transactions/authrep.xml {
    content_by_lua_block {
      ngx.exit(200)
    }
  }
--- upstream
  location / {
    content_by_lua_block {
        ngx.exit(200)
    }
  }

  location /401 {
    content_by_lua_block {
        ngx.exit(401)
    }
  }

  location /403 {
    content_by_lua_block {
        ngx.exit(403)
    }
  }
--- request eval
["GET /?user_key=foo", "GET /403?user_key=foo", "GET /401?user_key=foo"]
--- error_code eval
[ 201, 401, 401 ]

=== TEST 2: HTTP CODES policy placed after apicast
--- configuration
{
  "services": [
    {
      "id": 42,
      "backend_version":  1,
      "backend_authentication_type": "service_token",
      "backend_authentication_value": "token-value",
      "proxy": {
        "policy_chain": [
          {
            "name": "apicast.policy.apicast"
          },
          {
            "name": "statuscode_overwrite",
            "version": "builtin",
            "configuration": {
              "http_statuses": [
                {
                  "upstream": 200,
                  "apicast": 201
                },
                {
                  "upstream": 403,
                  "apicast": 401
                }
              ]
            }
          }
        ],
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/",
        "proxy_rules": [
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 1 }
        ]
      }
    }
  ]
}
--- backend
  location /transactions/authrep.xml {
    content_by_lua_block {
      ngx.exit(200)
    }
  }
--- upstream
  location / {
    content_by_lua_block {
        ngx.exit(200)
    }
  }

  location /401 {
    content_by_lua_block {
        ngx.exit(401)
    }
  }

  location /403 {
    content_by_lua_block {
        ngx.exit(403)
    }
  }
--- request eval
["GET /?user_key=foo", "GET /403?user_key=foo", "GET /401?user_key=foo"]
--- error_code eval
[ 201, 401, 401 ]
