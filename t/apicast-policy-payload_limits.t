use lib 't';
use Test::APIcast::Blackbox 'no_plan';

use Cwd qw(abs_path);


sub large_body {
  my $res = "";
  for (my $i=0; $i <= 1024; $i++) {
    $res = $res . "1111111 1111111 1111111 1111111\n";
  }
  return $res;
}

$ENV{'LARGE_BODY'} = large_body();

run_tests();

__DATA__

=== TEST 1: Request limit set to 0 allow request connection
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
        "proxy_rules": [
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 2 }
        ],
        "policy_chain": [
          {
            "name": "apicast.policy.payload_limits",
            "configuration": {
              "request": 0,
              "response": 0
            }
          },
          { "name": "apicast.policy.upstream",
            "configuration":
              {
                "rules": [ { "regex": "/", "url": "http://test:$TEST_NGINX_SERVER_PORT" } ]
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

--- request eval
"POST /test \n" . $ENV{LARGE_BODY}
--- response_body
yay, api backend
--- error_code: 200
--- no_error_log
[error]

=== TEST 2: Request limit set to 100 rejects the request
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
        "proxy_rules": [
          { "pattern": "/", "http_method": "POST", "metric_system_name": "hits", "delta": 2 }
        ],
        "policy_chain": [
          {
            "name": "apicast.policy.payload_limits",
            "configuration": {
              "request": 100,
              "response": 0
            }
          },
          { "name": "apicast.policy.upstream",
            "configuration":
              {
                "rules": [ { "regex": "/", "url": "http://test:$TEST_NGINX_SERVER_PORT" } ]
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

--- request eval
"POST /test \n" . $ENV{LARGE_BODY}
--- response_body
Payload Too Large
--- error_code: 413
--- no_error_log
[error]


=== TEST 3: Request body size smaller than the limit
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
        "proxy_rules": [
          { "pattern": "/", "http_method": "POST", "metric_system_name": "hits", "delta": 2 }
        ],
        "policy_chain": [
          {
            "name": "apicast.policy.payload_limits",
            "configuration": {
              "request": 10000000,
              "response": 0
            }
          },
          { "name": "apicast.policy.upstream",
            "configuration":
              {
                "rules": [ { "regex": "/", "url": "http://test:$TEST_NGINX_SERVER_PORT" } ]
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

--- request eval
"POST /test \n" . $ENV{LARGE_BODY}
--- response_body
yay, api backend
--- error_code: 200
--- no_error_log
[error]


=== TEST 4: Response limit set to 100 rejects the request
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
        "proxy_rules": [
          { "pattern": "/", "http_method": "POST", "metric_system_name": "hits", "delta": 2 }
        ],
        "policy_chain": [
          {
            "name": "apicast.policy.payload_limits",
            "configuration": {
              "request": 0,
              "response": 100
            }
          },
          { "name": "apicast.policy.upstream",
            "configuration":
              {
                "rules": [ { "regex": "/", "url": "http://test:$TEST_NGINX_SERVER_PORT" } ]
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
      local response = ""
      for var=0,20480 do
          response = response .. "XXXXXXXXXX"
      end
      ngx.header['Content-Length'] = #response
      ngx.say(response)
     }
  }

--- request
POST /test
--- error_code: 413
--- response_body eval
"Payload Too Large"
--- no_error_log
[error]


=== TEST 5: Request body size smaller than the limit
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
        "proxy_rules": [
          { "pattern": "/", "http_method": "POST", "metric_system_name": "hits", "delta": 2 }
        ],
        "policy_chain": [
          {
            "name": "apicast.policy.payload_limits",
            "configuration": {
              "request": 0,
              "response": 1000000
            }
          },
          { "name": "apicast.policy.upstream",
            "configuration":
              {
                "rules": [ { "regex": "/", "url": "http://test:$TEST_NGINX_SERVER_PORT" } ]
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
      local response = ""
      for var=0,20480 do
          response = response .. "XXXXXXXXXX"
      end
      ngx.header['Content-Length'] = #response
      ngx.say(response)
     }
  }

--- request eval
"POST /test \n"
--- error_code: 200
--- no_error_log
[error]
