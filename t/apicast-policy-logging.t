use lib 't';
use Test::APIcast::Blackbox 'no_plan';

# Test::Nginx does not allow to grep access logs, so we redirect them to
# stderr to be able to use "grep_error_log" by setting APICAST_ACCESS_LOG_FILE
$ENV{APICAST_ACCESS_LOG_FILE} = "$Test::Nginx::Util::ErrLogFile";

run_tests();

__DATA__

=== TEST 1: Enables access logs when configured to do so
--- configuration
{
  "services": [
    {
      "id": 42,
      "proxy": {
        "policy_chain": [
          {
            "name": "apicast.policy.logging",
            "configuration": {
              "enable_access_logs": true
            }
          },
          {
            "name": "apicast.policy.upstream",
            "configuration":
              {
                "rules": [ { "regex": "/", "url": "http://echo" } ]
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
       ngx.say('yay, api backend');
     }
  }
--- request
GET /
--- error_code: 200
--- grep_error_log eval
qr/"GET \W+ HTTP\/1.1" 200/
--- grep_error_log_out
"GET / HTTP/1.1" 200
--- no_error_log
[error]

=== TEST 2: Disables access logs when configured to do so
--- configuration
{
  "services": [
    {
      "id": 42,
      "proxy": {
        "policy_chain": [
          {
            "name": "apicast.policy.logging",
            "configuration": {
              "enable_access_logs": false
            }
          },
          {
            "name": "apicast.policy.upstream",
            "configuration":
              {
                "rules": [ { "regex": "/", "url": "http://echo" } ]
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
       ngx.say('yay, api backend');
     }
  }
--- request
GET /
--- error_code: 200
--- grep_error_log eval
qr/"GET \W+ HTTP\/1.1" 200/
--- grep_error_log_out
--- no_error_log
[error]

=== TEST 3: Enables access logs by default when the policy is included
--- configuration
{
  "services": [
    {
      "id": 42,
      "proxy": {
        "policy_chain": [
          {
            "name": "apicast.policy.logging",
            "configuration": { }
          },
          {
            "name": "apicast.policy.upstream",
            "configuration":
              {
                "rules": [ { "regex": "/", "url": "http://echo" } ]
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
       ngx.say('yay, api backend');
     }
  }
--- request
GET /
--- error_code: 200
--- grep_error_log eval
qr/"GET \W+ HTTP\/1.1" 200/
--- grep_error_log_out
"GET / HTTP/1.1" 200
--- no_error_log
[error]

=== TEST 4: service uses a custom access log format
--- configuration
{
  "services": [
    {
      "id": 42,
      "proxy": {
        "policy_chain": [
          {
            "name": "apicast.policy.logging",
            "configuration": {
                "custom_logging": "Status::{{ status }}"
            }
          },
          {
            "name": "apicast.policy.upstream",
            "configuration":
              {
                "rules": [ { "regex": "/", "url": "http://echo" } ]
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
       ngx.say('yay, api backend');
     }
  }
--- request
GET /
--- error_code: 200
--- grep_error_log_out
"^Status:: 200$"
--- no_error_log eval
[qr/\[error/, qr/GET \/ HTTP\/1.1\" 200/]

=== TEST 5: service uses a custom access log format with a valid condition
--- configuration
{
  "services": [
    {
      "id": 42,
      "proxy": {
        "policy_chain": [
          {
            "name": "apicast.policy.logging",
            "configuration": {
                "custom_logging": "Status::{{ status }}",
                "condition": {
                "operations": [
                  {"op": "==", "match": "{{status}}", "match_type": "liquid", "value": "200", "value_type": "plain"}
                ],
                "combine_op": "and"
              }
            }
          },
          {
            "name": "apicast.policy.upstream",
            "configuration":
              {
                "rules": [ { "regex": "/", "url": "http://echo" } ]
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
       ngx.say('yay, api backend');
     }
  }
--- request
GET /
--- error_code: 200
--- grep_error_log_out
"^Status:: 200$"
--- no_error_log eval
[qr/\[error/, qr/GET \/ HTTP\/1.1\" 200/]

=== TEST 6: service uses a custom access log format without a valid condition
--- configuration
{
  "services": [
    {
      "id": 42,
      "proxy": {
        "policy_chain": [
          {
            "name": "apicast.policy.logging",
            "configuration": {
                "custom_logging": "Status::{{ status }}",
                "condition": {
                "operations": [
                  {"op": "==", "match": "{{status}}", "match_type": "liquid", "value": "201", "value_type": "plain"}
                ],
                "combine_op": "and"
              }
            }
          },
          {
            "name": "apicast.policy.upstream",
            "configuration":
              {
                "rules": [ { "regex": "/", "url": "http://echo" } ]
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
       ngx.say('yay, api backend');
     }
  }
--- request
GET /
--- error_code: 200
--- no_error_log eval
[qr/^Status::200$/, qr/\[error/, qr/GET \/ HTTP\/1.1\" 200/]


=== TEST 7: service metadata is retrieved in the access_log
--- configuration
{
  "services": [
    {
      "id": 42,
      "proxy": {
        "policy_chain": [
          {
            "name": "apicast.policy.logging",
            "configuration": {
              "custom_logging": "Status::{{ status }} {{service.id}}"
            }
          },
          {
            "name": "apicast.policy.upstream",
            "configuration":
              {
                "rules": [ { "regex": "/", "url": "http://echo" } ]
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
       ngx.say('yay, api backend');
     }
  }
--- request
GET /
--- error_code: 200
--- grep_error_log_out
"^Status:: 200 42$"
--- no_error_log eval
[qr/\[error/, qr/GET \/ HTTP\/1.1\" 200/]
