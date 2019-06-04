use lib 't';
use Test::APIcast::Blackbox 'no_plan';

env_to_apicast(
    'APICAST_UPSTREAM_RETRY_CASES' => "error http_503 http_504",
);

# These tests rely on upstream that return different things on every call, so
# running them multiple times is not going to work.
repeat_each(1);

run_tests();

__DATA__

=== TEST 1: successful retry
This test defines an upstream that returns 503 2 times and 200 after that.
The number of retries is set to 2, so the response should be a 200 (gets a
503 in the first request, another 503 in the first retry, and 200 in the second
retry).
--- configuration
{
 "services": [
   {
     "id": 42,
     "proxy": {
       "policy_chain": [
         {
           "name": "apicast.policy.retry",
           "configuration": {
             "retries": 2
           }
         },
         {
           "name": "apicast.policy.upstream",
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
     local test_counter = ngx.shared.test_counter or 1
     if test_counter <= 2 then
       ngx.shared.test_counter = test_counter + 1
       ngx.exit(503)
     else
       ngx.say('yay, api backend');
     end
    }
 }
--- request
GET /
--- response_body
yay, api backend
--- error_code: 200
--- no_error_log
[error]

=== TEST 2: unsuccessful retry
This test defines an upstream that returns 503 5 times, and 200 after that.
The number of retries is set to 1, so the response should be a 503.
--- configuration
{
  "services": [
    {
      "id": 42,
      "proxy": {
        "policy_chain": [
          {
            "name": "apicast.policy.retry",
            "configuration": {
              "retries": 1,
              "retry_status_codes": [429],
              "retry_on_connection_errors": false
            }
          },
          {
            "name": "apicast.policy.upstream",
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
     local test_counter = ngx.shared.test_counter or 1
     if test_counter <= 5 then
       ngx.shared.test_counter = test_counter + 1
        ngx.status = 503
        ngx.say("An error in the upstream")
        ngx.exit(ngx.status)
     else
       ngx.say('yay, api backend');
     end
    }
 }
--- request
GET /
--- error_code: 503
--- response_body
An error in the upstream
--- no_error_log
[error]

=== TEST 3: error code not in APICAST_UPSTREAM_RETRY_CASES
In this test, the upstream returns a 502 error, which is not included in
APICAST_UPSTREAM_RETRY_CASES defined above, so the request should not be
retried.
--- configuration
{
 "services": [
   {
     "id": 42,
     "proxy": {
       "policy_chain": [
         {
           "name": "apicast.policy.retry",
           "configuration": {
             "retries": 5
           }
         },
         {
           "name": "apicast.policy.upstream",
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
     local test_counter = ngx.shared.test_counter or 1
     if test_counter <= 1 then
       ngx.shared.test_counter = test_counter + 1
        ngx.status = 502
        ngx.say("An error in the upstream")
        ngx.exit(ngx.status)
     else
       ngx.say('yay, api backend');
     end
    }
 }
--- request
GET /
--- response_body
yay, api backend
--- error_code: 502
--- response_body
An error in the upstream
--- no_error_log
[error]

=== TEST 4: works also with the APIcast policy
--- configuration
{
  "services": [
    {
      "id": 42,
      "backend_version": 1,
      "backend_authentication_type": "service_token",
      "backend_authentication_value": "token-value",
      "proxy": {
        "policy_chain": [
          {
            "name": "apicast.policy.retry",
            "configuration": {
              "retries": 5
            }
          },
          {
            "name": "apicast.policy.apicast"
          }
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
     local test_counter = ngx.shared.test_counter or 1
     if test_counter <= 2 then
       ngx.shared.test_counter = test_counter + 1
       ngx.exit(503)
     else
       ngx.say('yay, api backend');
     end
    }
 }
--- request
GET /?user_key=foo
--- response_body
yay, api backend
--- error_code: 200
--- no_error_log
[error]

=== TEST 5: nothing is retried if the retry policy is not in the chain
We needed to introduce the "proxy_next_upstream" directive in the config files
to make the retry policy work. This test checks that the directive does not
change the behavior the code had before introducing the policy. It should not
retry.
--- configuration
{
  "services": [
    {
      "id": 42,
      "proxy": {
        "policy_chain": [
          {
            "name": "apicast.policy.upstream",
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
      local test_counter = ngx.shared.test_counter or 1
      if test_counter <= 1 then
        ngx.shared.test_counter = test_counter + 1
        ngx.exit(503)
      else
        ngx.say('yay, api backend');
      end
     }
  }
--- request
GET /
--- error_code: 503
--- no_error_log
[error]

=== TEST 6: retry does not affect 3scale backend
This test verifies that the configuration of the retry policy does not affect
calls to the 3scale backend.
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
           "name": "apicast.policy.retry",
           "configuration": {
             "retries": 5
           }
         }
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
      ngx.exit(503)
    }
  }
--- upstream
 location / {
    content_by_lua_block {
      ngx.say('yay, api backend');
    }
 }
--- request
GET /?user_key=a_key
--- response_body
yay, api backend
--- error_code: 403
--- response_body chomp
Authentication failed
--- no_error_log
[error]

=== TEST 7: APICAST_UPSTREAM_RETRY_CASES is empty and retry policy enabled
proxy_next_upstream should be set to the default values: error and timeout.
This test verifies that a timeout is retried.
--- env eval
(
    'APICAST_UPSTREAM_RETRY_CASES' => "",
)
--- configuration
{
  "services": [
    {
      "id": 42,
      "proxy": {
        "policy_chain": [
          {
            "name": "apicast.policy.upstream_connection",
            "configuration": {
              "connect_timeout": 1,
              "send_timeout": 1,
              "read_timeout": 1
            }
          },
          {
            "name": "apicast.policy.retry",
            "configuration": {
              "retries": 2
            }
          },
          {
            "name": "apicast.policy.upstream",
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
     local test_counter = ngx.shared.test_counter or 1
     if test_counter <= 1 then
       ngx.shared.test_counter = test_counter + 1
       ngx.sleep(2)
       ngx.say('yay, api backend')
     else
       ngx.say('yay, api backend');
     end
    }
 }
--- request
GET /
--- response_body
yay, api backend
--- error_code: 200
--- error_log
upstream timed out

=== TEST 8: APICAST_UPSTREAM_RETRY_CASES is empty and retry policy not enabled
proxy_next_upstream should be set to the default values: error and timeout.
Even then, the request should not be retried if the retry policy is not
enabled. This test forces a timeout and verifies that the request is not
retried.
--- env eval
(
    'APICAST_UPSTREAM_RETRY_CASES' => "",
)
--- configuration
{
  "services": [
    {
      "id": 42,
      "proxy": {
        "policy_chain": [
          {
            "name": "apicast.policy.upstream_connection",
            "configuration": {
              "connect_timeout": 1,
              "send_timeout": 1,
              "read_timeout": 1
            }
          },
          {
            "name": "apicast.policy.upstream",
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
     local test_counter = ngx.shared.test_counter or 1
     if test_counter <= 1 then
       ngx.shared.test_counter = test_counter + 1
       ngx.sleep(2)
       ngx.say('yay, api backend')
     else
       ngx.say('yay, api backend');
     end
    }
 }
--- request
GET /
--- error_code: 504
--- error_log
upstream timed out