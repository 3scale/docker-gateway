use lib 't';
use Test::APIcast::Blackbox 'no_plan';

run_tests();

__DATA__

=== TEST 1: one transformation that matches
--- configuration
{
  "services": [
    {
      "id": 42,
      "proxy": {
        "policy_chain": [
          {
            "name": "rewrite_url_captures",
            "configuration": {
              "transformations": [
                {
                  "match_rule": "/{var_1}/{var_2}",
                  "template": "/{var_2}?my_arg={var_1}"
                }
              ]
            }
          },
          {
            "name": "upstream",
            "configuration": {
              "rules": [
                {
                  "regex": "/",
                  "url": "http://test:$TEST_NGINX_SERVER_PORT"
                }
              ]
            }
          }
        ]
      }
    }
  ]
}
--- upstream
  location / {
     content_by_lua_block {
       local assert = require('luassert')
       assert.equals('/def', ngx.var.uri)
       assert.equals('abc', ngx.req.get_uri_args()['my_arg'])
       ngx.say('yay, api backend');
     }
  }
--- request
GET /abc/def?user_key=value
--- response_body
yay, api backend
--- error_code: 200
--- no_error_log
[error]

=== TEST 2: several transformations that match
When there are several transformations that match, only the first one is applied.
--- configuration
{
  "services": [
    {
      "id": 42,
      "proxy": {
        "policy_chain": [
          {
            "name": "rewrite_url_captures",
            "configuration": {
              "transformations": [
                {
                  "match_rule": "/{var_1}/{var_2}",
                  "template": "/{var_2}?my_arg={var_1}"
                },
                {
                  "match_rule": "/{var_1}/{var_2}",
                  "template": "/{var_1}/{var_2}"
                }
              ]
            }
          },
          {
            "name": "upstream",
            "configuration": {
              "rules": [
                {
                  "regex": "/",
                  "url": "http://test:$TEST_NGINX_SERVER_PORT"
                }
              ]
            }
          }
        ]
      }
    }
  ]
}
--- upstream
  location / {
     content_by_lua_block {
       local assert = require('luassert')
       assert.equals('/def', ngx.var.uri)
       assert.equals('abc', ngx.req.get_uri_args()['my_arg'])
       ngx.say('yay, api backend');
     }
  }
--- request
GET /abc/def?user_key=value
--- response_body
yay, api backend
--- error_code: 200
--- no_error_log
[error]

=== TEST 3: none of the transformations match
When none of the transformations match, the URL is not modified.
--- configuration
{
  "services": [
    {
      "id": 42,
      "proxy": {
        "policy_chain": [
          {
            "name": "rewrite_url_captures",
            "configuration": {
              "transformations": [
                {
                  "match_rule": "/i_dont_match",
                  "template": "/{var_2}?my_arg={var_1}"
                },
                {
                  "match_rule": "/i_dont_match/{var_1}",
                  "template": "/{var_2}?my_arg={var_1}"
                }
              ]
            }
          },
          {
            "name": "upstream",
            "configuration": {
              "rules": [
                {
                  "regex": "/",
                  "url": "http://test:$TEST_NGINX_SERVER_PORT"
                }
              ]
            }
          }
        ]
      }
    }
  ]
}
--- upstream
  location / {
     content_by_lua_block {
       local assert = require('luassert')
       assert.equals('/abc', ngx.var.uri)
       assert.equals('def', ngx.req.get_uri_args()['query_arg'])
       ngx.say('yay, api backend');
     }
  }
--- request
GET /abc?query_arg=def&user_key=value
--- response_body
yay, api backend
--- error_code: 200
--- no_error_log
[error]

=== TEST 4: combine with APIcast policy
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
        "proxy_rules": [
          {
            "pattern": "/",
            "http_method": "GET",
            "metric_system_name": "hits",
            "delta": 2
          }
        ],
        "policy_chain": [
          {
            "name": "apicast.policy.apicast"
          },
          {
            "name": "apicast.policy.rewrite_url_captures",
            "configuration": {
              "transformations": [
                {
                  "match_rule": "/{var_1}/{var_2}",
                  "template": "/{var_2}?my_arg={var_1}"
                }
              ]
            }
          }
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
       local assert = require('luassert')
       assert.equals('/def', ngx.var.uri)
       assert.equals('abc', ngx.req.get_uri_args()['my_arg'])
       ngx.say('yay, api backend');
     }
  }
--- request
GET /abc/def?user_key=value
--- response_body
yay, api backend
--- error_code: 200
--- no_error_log
[error]

=== TEST 5: one transformation with method that doesn't match
--- configuration
{
  "services": [
    {
      "id": 42,
      "proxy": {
        "policy_chain": [
          {
            "name": "rewrite_url_captures",
            "configuration": {
              "transformations": [
                {
                  "match_rule": "/{var_1}/{var_2}",
                  "template": "/{var_2}?my_arg={var_1}",
                  "methods": ["PUT", "OPTIONS"]
                }
              ]
            }
          },
          {
            "name": "upstream",
            "configuration": {
              "rules": [
                {
                  "regex": "/",
                  "url": "http://test:$TEST_NGINX_SERVER_PORT"
                }
              ]
            }
          }
        ]
      }
    }
  ]
}
--- upstream
  location /abc/def {
     content_by_lua_block {
       ngx.exit(404)
     }
  }
--- request
GET /abc/def?user_key=xyz
--- error_code: 404
--- no_error_log
[error]

=== TEST 6: one transformation with method that matches
--- configuration
{
  "services": [
    {
      "id": 42,
      "proxy": {
        "policy_chain": [
          {
            "name": "rewrite_url_captures",
            "configuration": {
              "transformations": [
                {
                  "match_rule": "/{var_1}/{var_2}",
                  "template": "/{var_2}?my_arg={var_1}",
                  "methods": ["GET"]
                }
              ]
            }
          },
          {
            "name": "upstream",
            "configuration": {
              "rules": [
                {
                  "regex": "/",
                  "url": "http://test:$TEST_NGINX_SERVER_PORT"
                }
              ]
            }
          }
        ]
      }
    }
  ]
}
--- upstream
  location / {
     content_by_lua_block {
       local assert = require('luassert')
       assert.equals('/def', ngx.var.uri)
       assert.equals('abc', ngx.req.get_uri_args()['my_arg'])
       ngx.say('yay, api backend');
     }
  }
--- request
GET /abc/def?user_key=value
--- response_body
yay, api backend
--- error_code: 200
--- no_error_log
[error]

=== TEST 7: one transformation including an array of methods that matches
--- configuration
{
  "services": [
    {
      "id": 42,
      "proxy": {
        "policy_chain": [
          {
            "name": "rewrite_url_captures",
            "configuration": {
              "transformations": [
                {
                  "match_rule": "/{var_1}/{var_2}",
                  "template": "/{var_2}?my_arg={var_1}",
                  "methods": ["GET", "PUT", "POST"]
                }
              ]
            }
          },
          {
            "name": "upstream",
            "configuration": {
              "rules": [
                {
                  "regex": "/",
                  "url": "http://test:$TEST_NGINX_SERVER_PORT"
                }
              ]
            }
          }
        ]
      }
    }
  ]
}
--- upstream
  location / {
     content_by_lua_block {
       local assert = require('luassert')
       assert.equals('/def', ngx.var.uri)
       assert.equals('abc', ngx.req.get_uri_args()['my_arg'])
       ngx.say('yay, api backend');
     }
  }
--- request
PUT /abc/def?user_key=value
--- response_body
yay, api backend
--- error_code: 200
--- no_error_log
[error]
