use lib 't';
use Test::APIcast::Blackbox 'no_plan';

run_tests();

__DATA__

=== TEST 1: Use maintenance mode using default values
Testing 3 things:
1) Check default status code
2) Check default response message
3) Validates upstream doesn't get the request

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
          { "name": "apicast.policy.maintenance_mode" },
          { "name": "apicast.policy.apicast" }
        ],
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/",
        "proxy_rules": [
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 2 }
        ]
      }
    }
  ]
}
--- upstream
  location / {
    content_by_lua_block {
      local assert = require('luassert')
      assert.is_true(false)
    }
  }
--- request
GET /?user_key=value
--- response_body 
Service Unavailable - Maintenance
--- error_code: 503
--- no_error_log
[error]


=== TEST 2: Use maintenance mode using custom values
Testing 3 things:
1) Check custom status code
2) Check custom response message
3) Validates upstream doesn't get request

--- configuration
{
  "services": [{
    "id": 42,
    "backend_version": 1,
    "backend_authentication_type": "service_token",
    "backend_authentication_value": "token-value",
    "proxy": {
      "policy_chain": [{
          "name": "apicast.policy.maintenance_mode",
          "configuration": {
            "message": "Be back soon",
            "status": 501
          }
        },
        {
          "name": "apicast.policy.apicast"
        }
      ],
      "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/",
      "proxy_rules": [{
        "pattern": "/",
        "http_method": "GET",
        "metric_system_name": "hits",
        "delta": 2
      }]
    }
  }]
}
--- upstream
  location / {
    content_by_lua_block {
      local assert = require('luassert')
      assert.is_true(false)
    }
  }
--- request
GET /?user_key=value
--- response_body 
Be back soon
--- error_code: 501
--- no_error_log
[error]

=== TEST 3: Maintenance policy works when placed after the APIcast policy
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
          { "name": "apicast.policy.apicast" },
          { "name": "apicast.policy.maintenance_mode" }
        ],
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/",
        "proxy_rules": [
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 2 }
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
      assert.is_true(false)
    }
  }
--- request
GET /?user_key=value
--- response_body
Service Unavailable - Maintenance
--- error_code: 503
--- no_error_log
[error]

=== TEST 4: custom content-type
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
            "name": "apicast.policy.maintenance_mode",
            "configuration": {
              "message": "{ \"msg\": \"Be back soon\" }",
              "message_content_type": "application/json"
            }
          },
          { "name": "apicast.policy.apicast" }
        ],
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/",
        "proxy_rules": [
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 2 }
        ]
      }
    }
  ]
}
--- upstream
  location / {
    content_by_lua_block {
      local assert = require('luassert')
      assert.is_true(false)
    }
  }
--- request
GET /?user_key=value
--- response_body
{ "msg": "Be back soon" }
--- response_headers
Content-Type: application/json
--- error_code: 503
--- no_error_log
[error]


=== TEST 5: Maintenance mode is applied with routing policy + matching upstream condition

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
            "name": "apicast.policy.routing",
            "configuration": {
              "rules": [
                {
                    "url": "http://test:$TEST_NGINX_SERVER_PORT/b1",
                    "condition": {
                        "operations": [
                            {
                                "match": "path",
                                "op": "matches",
                                "value": "^(/backend1/.*|/backend1/?)"
                            }
                        ]
                    },
                    "replace_path": "{{uri | remove_first: '/backend1'}}"
                }
              ]
            }
          },
          { 
            "name": "apicast.policy.maintenance_mode",
            "configuration": {
                "condition": {
                    "operations": [
                        {
                            "left_type": "liquid",
                            "right_type": "plain",
                            "left": "{{ upstream.host }}:{{ upstream.port }}{{ upstream.path }}",
                            "right": "test:$TEST_NGINX_SERVER_PORT/b1/",
                            "op": "=="
                        }
                    ],
                    "combine_op": "and"
                }
            }
          },
          { "name": "apicast.policy.apicast" }
        ],
        "proxy_rules": [
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 2 }
        ]
      }
    }
  ]
}
--- upstream
  location /b1 {
    content_by_lua_block {
      local assert = require('luassert')
      assert.is_true(false)
    }
  }

--- request
GET /backend1?user_key=value
--- response_body 
Service Unavailable - Maintenance
--- error_code: 503
--- no_error_log
[error]


=== TEST 6: Maintenance mode is not applied with routing policy + non matching upstream condition

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
            "name": "apicast.policy.routing",
            "configuration": {
              "rules": [
                {
                  "url": "http://test:$TEST_NGINX_SERVER_PORT/b2",
                  "condition": {
                      "operations": [
                          {
                              "match": "path",
                              "op": "matches",
                              "value": "^(/backend2/.*|/backend2/?)"
                          }
                      ]
                  },
                  "replace_path": "{{uri | remove_first: '/backend2'}}"
                }
              ]
            }
          },
          { 
            "name": "apicast.policy.maintenance_mode",
            "configuration": {
              "condition": {
                  "operations": [
                      {
                          "left_type": "liquid",
                          "right_type": "plain",
                          "left": "{{ upstream.host }}:{{ upstream.port }}{{ upstream.path }}",
                          "right": "test:$TEST_NGINX_SERVER_PORT/b1/",
                          "op": "=="
                      }
                  ],
                  "combine_op": "and"
              }
            }
          },
          { "name": "apicast.policy.apicast" }
        ],
        "proxy_rules": [
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 2 }
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
  location /b2 {
     echo 'yay, api backend: $http_host';
  }
--- request
GET /backend2?user_key=value
--- response_body env
yay, api backend: test:$TEST_NGINX_SERVER_PORT
--- error_code: 200
--- no_error_log
[error]


=== TEST 7: Maintenance mode works with upstream policy + matching upstream condition

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
            "name": "apicast.policy.upstream",
            "configuration":
              {
                "rules": [ { "regex": "/backend1", "url": "http://test:$TEST_NGINX_SERVER_PORT/b1/" } ]
              }
          },
          { 
            "name": "apicast.policy.maintenance_mode",
            "configuration": {
              "condition": {
                  "operations": [
                      {
                          "left_type": "liquid",
                          "right_type": "plain",
                          "left": "{{ upstream.host }}:{{ upstream.port }}{{ upstream.path }}",
                          "right": "test:$TEST_NGINX_SERVER_PORT/b1/",
                          "op": "=="
                      }
                  ],
                  "combine_op": "and"
              }
            }
          },
          { "name": "apicast.policy.apicast" }
        ],
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/b2",
        "proxy_rules": [
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 2 }
        ]
      }
    }
  ]
}
--- upstream
  location /b1 {
    content_by_lua_block {
      local assert = require('luassert')
      assert.is_true(false)
    }
  }
--- request
GET /backend1?user_key=value
--- response_body 
Service Unavailable - Maintenance
--- error_code: 503
--- no_error_log
[error]


=== TEST 8: Maintenance mode works with api-backend

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
            "name": "apicast.policy.maintenance_mode",
            "configuration": {
              "condition": {
                  "operations": [
                      {
                          "left_type": "liquid",
                          "right_type": "plain",
                          "left": "{{ upstream.host }}:{{ upstream.port }}{{ upstream.path }}",
                          "right": "test:$TEST_NGINX_SERVER_PORT/api-backend/",
                          "op": "=="
                      }
                  ],
                  "combine_op": "and"
              }
            }
          },
          { "name": "apicast.policy.apicast" }
        ],
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/api-backend/",
        "proxy_rules": [
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 2 }
        ]
      }
    }
  ]
}
--- upstream
  location /api-backend/ {
    content_by_lua_block {
      local assert = require('luassert')
      assert.is_true(false)
    }
  }
--- request
GET /?user_key=value
--- response_body 
Service Unavailable - Maintenance
--- error_code: 503
--- no_error_log
[error]

=== TEST 9: Maintenance mode is applied with OR condition (1 matches)

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
            "name": "apicast.policy.maintenance_mode",
            "configuration": {
                "condition": {
                    "operations": [
                        {
                            "left_type": "liquid",
                            "right_type": "plain",
                            "left": "{{ upstream.path }}",
                            "right": "/foo",
                            "op": "=="
                        },
                        {
                            "left_type": "liquid",
                            "right_type": "plain",
                            "left": "{{ upstream.path }}",
                            "right": "/b1",
                            "op": "=="
                        }
                    ],
                    "combine_op": "or"
                }
            }
          },
          { "name": "apicast.policy.apicast" }
        ],
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/b1",
        "proxy_rules": [
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 2 }
        ]
      }
    }
  ]
}
--- upstream
  location /b1 {
    content_by_lua_block {
      local assert = require('luassert')
      assert.is_true(false)
    }
  }
--- request
GET /?user_key=value
--- response_body 
Service Unavailable - Maintenance
--- error_code: 503
--- no_error_log
[error]