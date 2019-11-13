use Test::APIcast::Blackbox 'no_plan';

run_tests();

__DATA__

=== TEST 1: sub operation
--- backend
  location /transactions/authrep.xml {
    content_by_lua_block {
      local expected = "service_token=token-value&service_id=42&usage%5Bhits%5D=2&user_key=value"
      require('luassert').same(ngx.decode_args(expected), ngx.req.get_uri_args(0))
    }
  }
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
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 2 }
        ],
        "policy_chain": [
          { "name": "apicast.policy.apicast" },
          {
            "name": "apicast.policy.url_rewriting",
            "configuration": {
              "commands": [
                { "op": "sub", "regex": "original", "replace": "new" }
              ]
            }
          }
        ]
      }
    }
  ]
}
--- upstream
  location ~ /xxx_new_yyy$ {
    content_by_lua_block {
      ngx.say('yay, api backend');
    }
  }
--- request
GET /xxx_original_yyy?user_key=value
--- response_body
yay, api backend
--- error_code: 200
--- no_error_log
[error]

=== TEST 2: gsub operation
--- backend
  location /transactions/authrep.xml {
    content_by_lua_block {
      local expected = "service_token=token-value&service_id=42&usage%5Bhits%5D=2&user_key=value"
      require('luassert').same(ngx.decode_args(expected), ngx.req.get_uri_args(0))
    }
  }
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
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 2 }
        ],
        "policy_chain": [
          { "name": "apicast.policy.apicast" },
          {
            "name": "apicast.policy.url_rewriting",
            "configuration": {
              "commands": [
                { "op": "gsub", "regex": "original", "replace": "new" }
              ]
            }
          }
        ]
      }
    }
  ]
}
--- upstream
  location ~ /aaa_new_bbb_new_ccc$ {
    content_by_lua_block {
      ngx.say('yay, api backend');
    }
  }
--- request
GET /aaa_original_bbb_original_ccc?user_key=value
--- response_body
yay, api backend
--- error_code: 200
--- no_error_log
[error]

=== TEST 3: ordered commands
Substitutions are applied in the order specified.
--- backend
  location /transactions/authrep.xml {
    content_by_lua_block {
      local expected = "service_token=token-value&service_id=42&usage%5Bhits%5D=2&user_key=value"
      require('luassert').same(ngx.decode_args(expected), ngx.req.get_uri_args(0))
    }
  }
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
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 2 }
        ],
        "policy_chain": [
          { "name": "apicast.policy.apicast" },
          {
            "name": "apicast.policy.url_rewriting",
            "configuration": {
              "commands": [
                { "op": "gsub", "regex": "aaa", "replace": "bbb", "options": "i" },
                { "op": "sub", "regex": "bbb", "replace": "ccc" },
                { "op": "sub", "regex": "ccc", "replace": "ddd" }
              ]
            }
          }
        ]
      }
    }
  ]
}
--- upstream
  location ~ /ddd_bbb$ {
    content_by_lua_block {
      ngx.say('yay, api backend');
    }
  }
--- request
GET /aaa_aaa?user_key=value
--- response_body
yay, api backend
--- error_code: 200
--- no_error_log
[error]

=== TEST 4: break
We need to test 2 things:
1) A break is only applied when the URL is rewritten.
2) When break is specified in a command, it will be the last one applied.
--- backend
  location /transactions/authrep.xml {
    content_by_lua_block {
      local expected = "service_token=token-value&service_id=42&usage%5Bhits%5D=2&user_key=value"
      require('luassert').same(ngx.decode_args(expected), ngx.req.get_uri_args(0))
    }
  }
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
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 2 }
        ],
        "policy_chain": [
          { "name": "apicast.policy.apicast" },
          {
            "name": "apicast.policy.url_rewriting",
            "configuration": {
              "commands": [
                { "op": "sub", "regex": "does_not_match", "replace": "a", "break": true },
                { "op": "sub", "regex": "aaa", "replace": "bbb" },
                { "op": "sub", "regex": "bbb", "replace": "ccc", "break": true },
                { "op": "sub", "regex": "ccc", "replace": "ddd" }
              ]
            }
          }
        ]
      }
    }
  ]
}
--- upstream
  location ~ /ccc$ {
    content_by_lua_block {
      ngx.say('yay, api backend');
    }
  }
--- request
GET /aaa?user_key=value
--- response_body
yay, api backend
--- error_code: 200
--- no_error_log
[error]

=== TEST 5: url rewriting policy placed before the apicast one in the chain
The url rewriting policy is placed before the apicast one in the policy chain,
this means that the request will be rewritten before matching the mapping
rules.
--- backend
  location /transactions/authrep.xml {
    content_by_lua_block {
      local expected = "service_token=token-value&service_id=42&usage%5Bhits%5D=2&user_key=value"
      require('luassert').same(ngx.decode_args(expected), ngx.req.get_uri_args(0))
    }
  }
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
          { "pattern": "/new", "http_method": "GET", "metric_system_name": "hits", "delta": 2 }
        ],
        "policy_chain": [
          {
            "name": "apicast.policy.url_rewriting",
            "configuration": {
              "commands": [
                { "op": "sub", "regex": "original", "replace": "new" }
              ]
            }
          },
          { "name": "apicast.policy.apicast" }
        ]
      }
    }
  ]
}
--- upstream
  location /new {
    content_by_lua_block {
      ngx.say('yay, api backend');
    }
  }
--- request
GET /original?user_key=value
--- response_body
yay, api backend
--- error_code: 200
--- no_error_log
[error]

=== TEST 6: "push" a query argument
Test that the 'push' operation adds the argument when it does not exist already.
When it exists, it adds a new value for it.
--- backend
  location /transactions/authrep.xml {
    content_by_lua_block {
      local expected = "service_token=token-value&service_id=42&usage%5Bhits%5D=2&user_key=value"
      require('luassert').same(ngx.decode_args(expected), ngx.req.get_uri_args(0))
    }
  }
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
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 2 }
        ],
        "policy_chain": [
          {
            "name": "apicast.policy.url_rewriting",
            "configuration": {
              "query_args_commands": [
                { "op": "push", "arg": "new_arg", "value": "a_value" },
                { "op": "push", "arg": "existing_arg", "value": "new_value" }
              ]
            }
          },
          { "name": "apicast.policy.apicast" }
        ]
      }
    }
  ]
}
--- upstream
  location / {
    content_by_lua_block {
      local luassert = require('luassert')
      luassert.equals('a_value', ngx.req.get_uri_args()['new_arg'])
      luassert.same({ 'original_value', 'new_value' }, ngx.req.get_uri_args()['existing_arg'])
      ngx.say('yay, api backend')
    }
  }
--- request
GET /?user_key=value&some_arg=1&existing_arg=original_value
--- response_body
yay, api backend
--- error_code: 200
--- no_error_log
[error]

=== TEST 7: "set" a query argument
Test that the 'set' operation replaces a query argument when it exists.
When the argument does not exist, the operation creates it.
--- backend
  location /transactions/authrep.xml {
    content_by_lua_block {
      local expected = "service_token=token-value&service_id=42&usage%5Bhits%5D=2&user_key=value"
      require('luassert').same(ngx.decode_args(expected), ngx.req.get_uri_args(0))
    }
  }
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
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 2 }
        ],
        "policy_chain": [
          {
            "name": "apicast.policy.url_rewriting",
            "configuration": {
              "query_args_commands": [
                { "op": "set", "arg": "an_arg", "value": "new_value" },
                { "op": "set", "arg": "not_in_the_original_query", "value": "val" }
              ]
            }
          },
          { "name": "apicast.policy.apicast" }
        ]
      }
    }
  ]
}
--- upstream
  location / {
    content_by_lua_block {
      local luassert = require('luassert')
      luassert.equals('new_value', ngx.req.get_uri_args()['an_arg'])
      luassert.equals('val', ngx.req.get_uri_args()['not_in_the_original_query'])
      ngx.say('yay, api backend')
    }
  }
--- request
GET /?user_key=value&an_arg=original_value&an_arg=another_val
--- response_body
yay, api backend
--- error_code: 200
--- no_error_log
[error]

=== TEST 8: "add" a query argument
Test that the 'add' operation adds a value to an argument only when it exists
already.
--- backend
  location /transactions/authrep.xml {
    content_by_lua_block {
      local expected = "service_token=token-value&service_id=42&usage%5Bhits%5D=2&user_key=value"
      require('luassert').same(ngx.decode_args(expected), ngx.req.get_uri_args(0))
    }
  }
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
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 2 }
        ],
        "policy_chain": [
          {
            "name": "apicast.policy.url_rewriting",
            "configuration": {
              "query_args_commands": [
                { "op": "add", "arg": "new_arg", "value": "a_value" },
                { "op": "add", "arg": "existing_arg", "value": "new_value" }
              ]
            }
          },
          { "name": "apicast.policy.apicast" }
        ]
      }
    }
  ]
}
--- upstream
  location / {
    content_by_lua_block {
      local luassert = require('luassert')
      luassert.same({ 'original_value', 'new_value' }, ngx.req.get_uri_args()['existing_arg'])
      luassert.is_nil(ngx.req.get_uri_args()['new_arg'])
      ngx.say('yay, api backend')
    }
  }
--- request
GET /?user_key=value&existing_arg=original_value
--- response_body
yay, api backend
--- error_code: 200
--- no_error_log
[error]

=== TEST 9: delete a query argument
--- backend
  location /transactions/authrep.xml {
    content_by_lua_block {
      local expected = "service_token=token-value&service_id=42&usage%5Bhits%5D=2&user_key=value"
      require('luassert').same(ngx.decode_args(expected), ngx.req.get_uri_args(0))
    }
  }
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
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 2 }
        ],
        "policy_chain": [
          {
            "name": "apicast.policy.url_rewriting",
            "configuration": {
              "query_args_commands": [
                { "op": "delete", "arg": "an_arg" }
              ]
            }
          },
          { "name": "apicast.policy.apicast" }
        ]
      }
    }
  ]
}
--- upstream
  location / {
    content_by_lua_block {
      local luassert = require('luassert')
      luassert.is_nil(ngx.req.get_uri_args()['an_arg'])
      ngx.say('yay, api backend')
    }
  }
--- request
GET /?user_key=value&an_arg=1
--- response_body
yay, api backend
--- error_code: 200
--- no_error_log
[error]

=== TEST 10: modify query args using liquid templating
--- backend
  location /transactions/authrep.xml {
    content_by_lua_block {
      local expected = "service_token=token-value&service_id=42&usage%5Bhits%5D=2&user_key=value"
      require('luassert').same(ngx.decode_args(expected), ngx.req.get_uri_args(0))
    }
  }
--- configuration
{
   "services":[
      {
         "id":42,
         "backend_version":1,
         "backend_authentication_type":"service_token",
         "backend_authentication_value":"token-value",
         "proxy":{
            "api_backend":"http://test:$TEST_NGINX_SERVER_PORT/",
            "proxy_rules":[
               {
                  "pattern":"/",
                  "http_method":"GET",
                  "metric_system_name":"hits",
                  "delta":2
               }
            ],
            "policy_chain":[
               {
                  "name":"apicast.policy.url_rewriting",
                  "configuration":{
                     "query_args_commands":[
                        {
                           "op":"push",
                           "arg":"a",
                           "value":"{{'a' | md5 }}",
                           "value_type":"liquid"
                        },
                        {
                           "op":"set",
                           "arg":"b",
                           "value":"{{'b' | md5 }}",
                           "value_type":"liquid"
                        },
                        {
                           "op":"add",
                           "arg":"c",
                           "value":"{{'c' | md5 }}",
                           "value_type":"liquid"
                        }
                     ]
                  }
               },
               {
                  "name":"apicast.policy.apicast"
               }
            ]
         }
      }
   ]
}
--- upstream
  location / {
    content_by_lua_block {
      local luassert = require('luassert')
      luassert.equals(ngx.md5('a'), ngx.req.get_uri_args()['a'])
      luassert.equals(ngx.md5('b'), ngx.req.get_uri_args()['b'])
      luassert.same({ 'original_val', ngx.md5('c') }, ngx.req.get_uri_args()['c'])
      ngx.say('yay, api backend')
    }
  }
--- request
GET /?user_key=value&c=original_val
--- response_body
yay, api backend
--- error_code: 200
--- no_error_log
[error]

=== TEST 11: modify query params and use upstream policy
The goal of this test is to verify that when the query args are modified using
the URL rewriting policy, the upstream specified in the upstream policy
receives the correct values.
--- backend
  location /transactions/authrep.xml {
    content_by_lua_block {
      local expected = "service_token=token-value&service_id=42&usage%5Bhits%5D=2&user_key=uk"
      require('luassert').same(ngx.decode_args(expected), ngx.req.get_uri_args(0))
    }
  }
--- configuration
{
  "services": [
    {
      "id": 42,
      "backend_version":  1,
      "backend_authentication_type": "service_token",
      "backend_authentication_value": "token-value",
      "proxy": {
        "api_backend": "http://example.com:80/",
        "proxy_rules": [
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 2 }
        ],
        "policy_chain": [
          {
            "name": "apicast.policy.url_rewriting",
            "configuration": {
              "query_args_commands": [
                { "op": "push", "arg": "new_arg", "value": "a_value" }
              ]
            }
          },
          {
            "name": "apicast.policy.upstream",
            "configuration": {
              "rules": [ { "regex": "/", "url": "http://test:$TEST_NGINX_SERVER_PORT" } ]
            }
          },
          { "name": "apicast.policy.apicast" }
        ]
      }
    }
  ]
}
--- upstream
  location / {
     content_by_lua_block {
       require('luassert').are.equal('GET /?user_key=uk&new_arg=a_value HTTP/1.1',
                                     ngx.var.request)
       ngx.say('yay, api backend');
     }
  }
--- request
GET /?user_key=uk
--- response_body
yay, api backend
--- error_code: 200
--- no_error_log
[error]

=== TEST 12: modify query args using liquid and one of the vars exposed
The goal of this test is to check that we can use liquid with the vars that are
not in the policies context, but are exposed by default (uri, host, etc.).
We are going to use "uri" in this case.
--- backend
  location /transactions/authrep.xml {
    content_by_lua_block {
      local expected = "service_token=token-value&service_id=42&usage%5Bhits%5D=2&user_key=uk"
      require('luassert').same(ngx.decode_args(expected), ngx.req.get_uri_args(0))
    }
  }
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
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 2 }
        ],
        "policy_chain": [
          {
            "name": "apicast.policy.url_rewriting",
            "configuration": {
              "query_args_commands": [
                { "op": "push", "arg": "new_arg", "value": "{{ uri }}", "value_type": "liquid" }
              ]
            }
          },
          { "name": "apicast.policy.apicast" }
        ]
      }
    }
  ]
}
--- upstream
  location / {
     content_by_lua_block {
     ngx.log(ngx.WARN, 'request: ', ngx.var.request)

       require('luassert').are.equal('GET /abc?user_key=uk&new_arg=%2Fabc HTTP/1.1',
                                     ngx.var.request)
       ngx.say('yay, api backend');
     }
  }
--- request
GET /abc?user_key=uk
--- response_body
yay, api backend
--- error_code: 200
--- no_error_log
[error]

=== TEST 13: url rewriting policy placed before the apicast with special chars
The url rewriting policy is placed before the apicast one in the policy chain,
this means that the request will be rewritten before matching the mapping rules
and it'll use special character to make sure that the encode works correctly
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
      "backend_version":  1,
      "backend_authentication_type": "service_token",
      "backend_authentication_value": "token-value",
      "proxy": {
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/",
        "proxy_rules": [
          { "pattern": "/new%20/foo/", "http_method": "GET", "metric_system_name": "hits", "delta": 2 }
        ],
        "policy_chain": [
          {
            "name": "apicast.policy.url_rewriting",
            "configuration": {
              "commands": [
                { "op": "sub", "regex": "original", "replace": "new /foo/" }
              ]
            }
          },
          { "name": "apicast.policy.apicast" }
        ]
      }
    }
  ]
}
--- upstream
  location /new {
    content_by_lua_block {
      ngx.say('yay, api backend');
    }
  }
--- request
GET /original?user_key=value
--- response_body
yay, api backend
--- error_code: 200
--- no_error_log
[error]
