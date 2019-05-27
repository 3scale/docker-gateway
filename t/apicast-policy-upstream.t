use lib 't';
use Test::APIcast::Blackbox 'no_plan';

run_tests();

__DATA__

=== TEST 1: single rule that matches
In this test, we provide a rule that matches the request and sets the upstream
to the one we have set up. If this was not working we would notice, because
"api_backend" in the service configuration points to an invalid one.
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
          { "name": "apicast.policy.upstream",
            "configuration":
              {
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
  location /a_path {
     content_by_lua_block {
       require('luassert').are.equal('GET /a_path?user_key=uk&a_param=a_value HTTP/1.1',
                                     ngx.var.request)
       ngx.say('yay, api backend');
     }
  }
--- request
GET /a_path?user_key=uk&a_param=a_value
--- response_body
yay, api backend
--- error_code: 200
--- no_error_log
[error]

=== TEST 2: multiple rules that match
In this example, we provide a rule that does not match and two that do.
Rules should be matched in order, so we set the first rule that matches to the
upstream we have set up.
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
        "api_backend": "http://example:80/",
        "proxy_rules": [
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 2 }
        ],
        "policy_chain": [
          {
            "name": "apicast.policy.upstream",
            "configuration":
              {
                "rules": [
                  { "regex": "/i_dont_match", "url": "http://example.com" },
                  { "regex": "/", "url": "http://test:$TEST_NGINX_SERVER_PORT" },
                  { "regex": "/abc", "url": "http://example.com" }
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
  location /a_path {
     content_by_lua_block {
       require('luassert').are.equal('GET /a_path?user_key=uk&a_param=a_value HTTP/1.1',
                                     ngx.var.request)
       ngx.say('yay, api backend');
     }
  }
--- request
GET /a_path?user_key=uk&a_param=a_value
--- response_body
yay, api backend
--- error_code: 200
--- no_error_log
[error]

=== TEST 3: non-matching rules
In this example, none of the rules match, so the request will go to the
upstream in 'api_backend'.
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
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT",
        "proxy_rules": [
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 2 }
        ],
        "policy_chain": [
          {
            "name": "apicast.policy.upstream",
            "configuration":
              {
                "rules": [
                  { "regex": "/i_dont_match", "url": "http://example.com" },
                  { "regex": "/i_dont_either", "url": "http://example.com" },
                  { "regex": "/nope", "url": "http://example.com" }
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
  location /a_path {
     content_by_lua_block {
       require('luassert').are.equal('GET /a_path?user_key=uk&a_param=a_value HTTP/1.1',
                                     ngx.var.request)
       ngx.say('yay, api backend');
     }
  }
--- request
GET /a_path?user_key=uk&a_param=a_value
--- response_body
yay, api backend
--- error_code: 200
--- no_error_log
[error]

=== TEST 4: rule that matches contains url with path
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
        "api_backend": "http://example.com",
        "proxy_rules": [
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 2 }
        ],
        "policy_chain": [
          {
            "name": "apicast.policy.upstream",
            "configuration":
              {
                "rules": [
                  {
                    "regex": "/",
                    "url": "http://test:$TEST_NGINX_SERVER_PORT/path_in_the_rule"
                  }
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
  location /path_in_the_rule {
     echo $request;
  }
--- request
GET /some_path?user_key=uk&a_param=a_value
--- response_body
GET /path_in_the_rule/some_path?user_key=uk&a_param=a_value HTTP/1.1
--- error_code: 200
--- no_error_log
[error]

=== TEST 5: rule that matches a POST request
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
          { "pattern": "/", "http_method": "POST", "metric_system_name": "hits", "delta": 2 }
        ],
        "policy_chain": [
          { "name": "apicast.policy.upstream",
            "configuration":
              {
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
  location /a_path {
     content_by_lua_block {
       local luassert = require('luassert')

       luassert.are.equal('POST /a_path HTTP/1.1', ngx.var.request)

       ngx.req.read_body()
       local post_args = ngx.req.get_post_args()
       luassert.are.equal('uk', post_args['user_key'])
       luassert.are.equal('a_value', post_args['a_param'])

       ngx.say('yay, api backend')
     }
  }
--- request
POST /a_path
user_key=uk&a_param=a_value
--- response_body
yay, api backend
--- error_code: 200
--- no_error_log
[error]



=== TEST 6: without apicast policy
Upstream policy should work if used standalone without apicast policy.
--- configuration
{
  "services": [
    {
      "proxy": {
        "policy_chain": [
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
  location /a_path {
     content_by_lua_block {
       require('luassert').are.equal('GET /a_path?query HTTP/1.1',
                                     ngx.var.request)
       ngx.say('yay, api backend');
     }
  }
--- request
GET /a_path?query
--- response_body
yay, api backend
--- error_code: 200
--- no_error_log
[error]



=== TEST 7: using echo
Upstream policy should work with internal echo API.
--- configuration
{
  "services": [
    {
      "proxy": {
        "policy_chain": [
          { "name": "apicast.policy.upstream",
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
--- request
GET /a_path
--- response_body
GET /a_path HTTP/1.1
X-Real-IP: 127.0.0.1
Host: echo
--- error_code: 200
--- no_error_log
[error]



=== TEST 8: TLS upstream
--- configuration random_port env
{
  "services": [
    {
      "proxy": {
        "policy_chain": [
          { "name": "apicast.policy.upstream",
            "configuration":
              {
                "rules": [ { "regex": "/", "url": "https://test:$TEST_NGINX_RANDOM_PORT" } ]
              }
          }
        ]
      }
    }
  ]
}
--- upstream random_port env
  listen $TEST_NGINX_RANDOM_PORT ssl;

  ssl_certificate $TEST_NGINX_SERVER_ROOT/html/server.crt;
  ssl_certificate_key $TEST_NGINX_SERVER_ROOT/html/server.key;

  location / {
     echo 'scheme: $scheme';
     echo 'server_port: $server_port';
     echo 'ssl_server_name: $ssl_server_name';
  }
--- request
GET /?user_key=uk
--- response_body random_port env
scheme: https
server_port: $TEST_NGINX_RANDOM_PORT
ssl_server_name: test
--- error_code: 200
--- no_error_log
[error]
--- user_files
>>> server.crt
-----BEGIN CERTIFICATE-----
MIIB0DCCAXegAwIBAgIJAISY+WDXX2w5MAoGCCqGSM49BAMCMEUxCzAJBgNVBAYT
AkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRn
aXRzIFB0eSBMdGQwHhcNMTYxMjIzMDg1MDExWhcNMjYxMjIxMDg1MDExWjBFMQsw
CQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJu
ZXQgV2lkZ2l0cyBQdHkgTHRkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEhkmo
6Xp/9W9cGaoGFU7TaBFXOUkZxYbGXQfxyZZucIQPt89+4r1cbx0wVEzbYK5wRb7U
iWhvvvYDltIzsD75vqNQME4wHQYDVR0OBBYEFOBBS7ZF8Km2wGuLNoXFAcj0Tz1D
MB8GA1UdIwQYMBaAFOBBS7ZF8Km2wGuLNoXFAcj0Tz1DMAwGA1UdEwQFMAMBAf8w
CgYIKoZIzj0EAwIDRwAwRAIgZ54vooA5Eb91XmhsIBbp12u7cg1qYXNuSh8zih2g
QWUCIGTHhoBXUzsEbVh302fg7bfRKPCi/mcPfpFICwrmoooh
-----END CERTIFICATE-----
>>> server.key
-----BEGIN EC PARAMETERS-----
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIFCV3VwLEFKz9+yTR5vzonmLPYO/fUvZiMVU1Hb11nN8oAoGCCqGSM49
AwEHoUQDQgAEhkmo6Xp/9W9cGaoGFU7TaBFXOUkZxYbGXQfxyZZucIQPt89+4r1c
bx0wVEzbYK5wRb7UiWhvvvYDltIzsD75vg==
-----END EC PRIVATE KEY-----

=== TEST 9: before the URL rewriting policy in the chain
Check that the upstream policy matches the original path of the request
instead of the rewritten one.
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
            "name": "apicast.policy.upstream",
            "configuration": {
              "rules": [ { "regex": "/original", "url": "http://test:$TEST_NGINX_SERVER_PORT" } ]
            }
          },
          {
            "name": "apicast.policy.url_rewriting",
            "configuration": {
              "commands": [
                { "op": "gsub", "regex": "/original", "replace": "/rewritten" }
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
  location /rewritten {
     content_by_lua_block {
       require('luassert').are.equal('GET /rewritten?user_key=uk&a_param=a_value HTTP/1.1',
                                     ngx.var.request)
       ngx.say('yay, api backend');
     }
  }
--- request
GET /original?user_key=uk&a_param=a_value
--- response_body
yay, api backend
--- error_code: 200
--- no_error_log
[error]

=== TEST 10: after the URL rewriting policy in the chain
Check that the upstream policy matches the rewritten path of the request
instead of the original one.
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
              "commands": [
                { "op": "gsub", "regex": "/original", "replace": "/rewritten" }
              ]
            }
          },
          {
            "name": "apicast.policy.upstream",
            "configuration": {
              "rules": [ { "regex": "/rewritten", "url": "http://test:$TEST_NGINX_SERVER_PORT" } ]
            }
          },
          { "name": "apicast.policy.apicast" }
        ]
      }
    }
  ]
}
--- upstream
  location /rewritten {
     content_by_lua_block {
       require('luassert').are.equal('GET /rewritten?user_key=uk&a_param=a_value HTTP/1.1',
                                     ngx.var.request)
       ngx.say('yay, api backend');
     }
  }
--- request
GET /original?user_key=uk&a_param=a_value
--- response_body
yay, api backend
--- error_code: 200
--- no_error_log
[error]


=== TEST 11: Test upstream api with uppercase letters.
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
        "api_backend": "http://example.com",
        "proxy_rules": [
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 2 }
        ],
        "policy_chain": [
          {
            "name": "apicast.policy.upstream",
            "configuration":
              {
                "rules": [
                  {
                    "regex": "/",
                    "url": "http://test:$TEST_NGINX_SERVER_PORT/PATH_IN_THE_RULE"
                  }
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
  location /PATH_IN_THE_RULE {
     echo $request;
  }
--- request
GET /some_path?user_key=uk&a_param=a_value
--- response_body
GET /PATH_IN_THE_RULE/some_path?user_key=uk&a_param=a_value HTTP/1.1
--- error_code: 200
--- no_error_log
[error]
