use lib 't';
use Test::APIcast::Blackbox 'no_plan';

run_tests();

__DATA__

=== TEST 1: Enables extra metric with a rule
--- configuration
{
  "services": [
    {
      "id": 42,
      "backend_version":  1,
      "backend_authentication_type": "service_token",
      "backend_authentication_value": "token-value",
      "proxy": {
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/",
        "proxy_rules": [
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 1 }
        ],
        "policy_chain": [
          {
            "name": "apicast.policy.custom_metrics",
            "configuration": {
              "rules": [
                {
                  "condition": {
                    "operations": [
                      {"op": "==", "left": "{{status}}", "left_type": "liquid", "right": "200"}
                    ],
                    "combine_op": "and"
                  },
                  "metric": "foo",
                  "increment": "1"
                }
              ]
            }
          },
          {
            "name": "apicast.policy.apicast"
          }
        ]
      }
    }
  ]
}

--- backend
  location /transactions/authrep.xml {

    content_by_lua_block {
      local test_counter = ngx.shared.test_counter or 1
      if test_counter == 1 then
        ngx.shared.test_counter = test_counter + 1
        ngx.exit(200)
      end

      if test_counter == 2 then
        local expected = "service_token=token-value&service_id=42&usage%5Bfoo%5D=1&usage%5Bhits%5D=1&user_key=value"
        require('luassert').same(ngx.decode_args(expected), ngx.req.get_uri_args(0))
        ngx.exit(200)
      end
    }
  }
  # Report transactions for the first one
  location /transactions.xml {
    content_by_lua_block {
      ngx.req.read_body()
      local post_args = ngx.req.get_post_args()
      require('luassert').same(post_args["transactions[0][usage][foo]"], "1")
      require('luassert').same(post_args["transactions[0][user_key]"], "value")
      ngx.exit(200)
    }
  }
--- upstream
  location / {
     content_by_lua_block {
       ngx.say('yay, api backend');
     }
  }
--- request eval
["GET /?user_key=value", "GET /?user_key=value"]
--- error_code eval
[200, 200]
--- no_error_log
[error]

=== TEST 2: Enables extra metric with increment based on header
--- configuration
{
  "services": [
    {
      "id": 42,
      "backend_version":  1,
      "backend_authentication_type": "service_token",
      "backend_authentication_value": "token-value",
      "proxy": {
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/",
        "proxy_rules": [
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 1 }
        ],
        "policy_chain": [
          {
            "name": "apicast.policy.custom_metrics",
            "configuration": {
              "rules": [
                {
                  "condition": {
                    "operations": [
                      {"op": "==", "left": "{{status}}", "left_type": "liquid", "right": "200"}
                    ],
                    "combine_op": "and"
                  },
                  "metric": "foo",
                  "increment": "{{ resp.headers['increment'] }}"
                }
              ]
            }
          },
          {
            "name": "apicast.policy.apicast"
          }
        ]
      }
    }
  ]
}
--- backend
  location /transactions/authrep.xml {

    content_by_lua_block {
      local test_counter = ngx.shared.test_counter or 1
      if test_counter == 1 then
        ngx.shared.test_counter = test_counter + 1
        ngx.exit(200)
      end

      if test_counter == 2 then
        local expected = "service_token=token-value&service_id=42&usage%5Bfoo%5D=2&usage%5Bhits%5D=1&user_key=value"
        require('luassert').same(ngx.decode_args(expected), ngx.req.get_uri_args(0))
        ngx.exit(200)
      end
    }
  }

  # Report transactions for the first one
  location /transactions.xml {
    content_by_lua_block {
      ngx.req.read_body()
      local post_args = ngx.req.get_post_args()
      require('luassert').same(post_args["transactions[0][usage][foo]"], "2")
      require('luassert').same(post_args["transactions[0][user_key]"], "value")
      ngx.exit(200)
    }
  }
--- upstream
  location / {
    content_by_lua_block {
      ngx.header['increment'] = '2'
      ngx.say('yay, api backend');
    }
  }
--- request eval
["GET /?user_key=value", "GET /?user_key=value"]
--- error_code eval
[200, 200]
--- no_error_log
[error]


=== TEST 3: Enables extra metric using liquid filter
--- configuration
{
  "services": [
    {
      "id": 42,
      "backend_version":  1,
      "backend_authentication_type": "service_token",
      "backend_authentication_value": "token-value",
      "proxy": {
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/",
        "proxy_rules": [
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 1 }
        ],
        "policy_chain": [
          {
            "name": "apicast.policy.custom_metrics",
            "configuration": {
              "rules": [
                {
                  "condition": {
                    "operations": [
                      {"op": "==", "left": "{{status}}", "left_type": "liquid", "right": "200"}
                    ],
                    "combine_op": "and"
                  },
                  "metric": "foo_{{status}}",
                  "increment": "1"
                }
              ]
            }
          },
          {
            "name": "apicast.policy.apicast"
          }
        ]
      }
    }
  ]
}

--- backend
  location /transactions/authrep.xml {

    content_by_lua_block {
      local test_counter = ngx.shared.test_counter or 1
      if test_counter == 1 then
        ngx.shared.test_counter = test_counter + 1
        ngx.exit(200)
      end

      if test_counter == 2 then
        local expected = "service_token=token-value&service_id=42&usage%5Bfoo_200%5D=1&usage%5Bhits%5D=1&user_key=value"
        require('luassert').same(ngx.decode_args(expected), ngx.req.get_uri_args(0))
        ngx.exit(200)
      end
    }
  }

  # Report transactions for the first one
  location /transactions.xml {
    content_by_lua_block {
      ngx.req.read_body()
      local post_args = ngx.req.get_post_args()
      require('luassert').same(post_args["transactions[0][usage][foo_200]"], "1")
      require('luassert').same(post_args["transactions[0][user_key]"], "value")
      ngx.exit(200)
    }
  }
--- upstream
  location / {
     content_by_lua_block {
       ngx.say('yay, api backend');
     }
  }
--- request eval
["GET /?user_key=value", "GET /?user_key=value"]
--- error_code eval
[200, 200]
--- no_error_log
[error]

=== TEST 4: Rule does not match, metric is not added
--- configuration
{
  "services": [
    {
      "id": 42,
      "backend_version":  1,
      "backend_authentication_type": "service_token",
      "backend_authentication_value": "token-value",
      "proxy": {
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/",
        "proxy_rules": [
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 1 }
        ],
        "policy_chain": [
          {
            "name": "apicast.policy.custom_metrics",
            "configuration": {
              "rules": [
                {
                  "condition": {
                    "operations": [
                      {"op": "==", "left": "{{status}}", "left_type": "liquid", "right": "400"}
                    ],
                    "combine_op": "and"
                  },
                  "metric": "foo_{{status}}",
                  "increment": "1"
                }
              ]
            }
          },
          {
            "name": "apicast.policy.apicast"
          }
        ]
      }
    }
  ]
}

--- backend
  location /transactions/authrep.xml {

    content_by_lua_block {
      local test_counter = ngx.shared.test_counter or 1
      if test_counter == 1 then
        ngx.shared.test_counter = test_counter + 1
        ngx.exit(200)
      end

      if test_counter == 2 then
        local expected = "service_token=token-value&service_id=42&usage%5Bhits%5D=1&user_key=value"
        require('luassert').same(ngx.decode_args(expected), ngx.req.get_uri_args(0))
        ngx.exit(200)
      end
    }
  }

  # Report transactions for the first one
  location /transactions.xml {
    content_by_lua_block {
      ngx.req.read_body()
      local post_args = ngx.req.get_post_args()
      require('luassert').same(post_args["transactions[0][usage][foo_400]"], "1")
      require('luassert').same(post_args["transactions[0][user_key]"], "value")
      ngx.exit(200)
    }
  }
--- upstream
  location / {
     content_by_lua_block {
       ngx.say('yay, api backend');
     }
  }
--- request eval
["GET /?user_key=value", "GET /?user_key=value"]
--- error_code eval
[200, 200]
--- no_error_log
[error]


=== TEST 5: Multiple rules
--- configuration
{
  "services": [
    {
      "id": 42,
      "backend_version":  1,
      "backend_authentication_type": "service_token",
      "backend_authentication_value": "token-value",
      "proxy": {
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/",
        "proxy_rules": [
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 1 }
        ],
        "policy_chain": [
          {
            "name": "apicast.policy.custom_metrics",
            "configuration": {
              "rules": [
                {
                  "condition": {
                    "operations": [
                      {"op": "==", "left": "{{status}}", "left_type": "liquid", "right": "200"}
                    ],
                    "combine_op": "and"
                  },
                  "metric": "foo",
                  "increment": "1"
                },
                {
                  "condition": {
                    "operations": [
                      {"op": "==", "left": "{{status}}", "left_type": "liquid", "right": "200"}
                    ],
                    "combine_op": "and"
                  },
                  "metric": "hits_{{status}}",
                  "increment": "1"
                }
              ]
            }
          },
          {
            "name": "apicast.policy.apicast"
          }
        ]
      }
    }
  ]
}

--- backend
  location /transactions/authrep.xml {

    content_by_lua_block {
      local test_counter = ngx.shared.test_counter or 1
      if test_counter == 1 then
        ngx.shared.test_counter = test_counter + 1
        ngx.exit(200)
      end

      if test_counter == 2 then
        local expected = "service_token=token-value&service_id=42&usage%5Bfoo%5D=1&usage%5Bhits_200%5D=1&usage%5Bhits%5D=1&user_key=value"
        require('luassert').same(ngx.decode_args(expected), ngx.req.get_uri_args(0))
        ngx.exit(200)
      end
    }
  }

  # Report transactions for the first one
  location /transactions.xml {
    content_by_lua_block {
      ngx.req.read_body()
      local post_args = ngx.req.get_post_args()
      require('luassert').same(post_args["transactions[0][usage][foo]"], "1")
      require('luassert').same(post_args["transactions[0][usage][hits_200]"], "1")
      require('luassert').same(post_args["transactions[0][user_key]"], "value")
      ngx.exit(200)
    }
  }
--- upstream
  location / {
     content_by_lua_block {
       ngx.say('yay, api backend');
     }
  }
--- request eval
["GET /?user_key=value", "GET /?user_key=value"]
--- error_code eval
[200, 200]
--- no_error_log
[error]

