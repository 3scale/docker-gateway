use lib 't';
use Test::APIcast::Blackbox 'no_plan';

use Cwd qw(abs_path);

our $rsa = `cat t/fixtures/rsa.pem`;

run_tests();

__DATA__

=== TEST 1: 'set' operation in request headers
We test 4 things:
1) Set op with a header that does not exist creates it with the given value.
2) Set op with a header that exists, clears it and sets the given value.
3) Set op with an empty value deletes the header.
4) Check that the headers are received in the upstream but not in the response
   of the original request.
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
            "name": "apicast.policy.headers",
            "configuration":
              {
                "request":
                  [
                    { "op": "set", "header": "New-Header", "value": "config_value_nh" },
                    { "op": "set", "header": "Existing-Header", "value": "config_value_eh" },
                    { "op": "set", "header": "Header-To-Delete", "value": "" }
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
       assert.same('config_value_nh', ngx.req.get_headers()['New-Header'])
       assert.same('config_value_eh', ngx.req.get_headers()['Existing-Header'])
       assert.is_nil(ngx.req.get_headers()['Header-To-Delete'])
       ngx.say('yay, api backend');
     }
  }
--- request
GET /?user_key=value
--- more_headers
Existing-Header: request_value_eh1
Existing-Header: request_value_eh2
Header-To-Delete: request_value_htd
--- response_body
yay, api backend
--- response_headers
New-Header:
Existing-Header:
Header-To-Delete:
--- error_code: 200
--- no_error_log
[error]

=== TEST 2: 'push' operation in request headers
We test 3 things:
1) Push op with a header that does not exist creates it with the given value.
2) Push op with a header that exists, creates a new header with the same name
   and the given value.
3) Check that the headers are received in the upstream but not in the response
   of the original request.
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
            "name": "apicast.policy.headers",
            "configuration":
              {
                "request":
                  [
                    { "op": "push", "header": "New-Header", "value": "config_value_nh" },
                    { "op": "push", "header": "Existing-Header", "value": "config_value_eh" }
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
       assert.same('config_value_nh', ngx.req.get_headers()['New-Header'])
       local existing_header_values = ngx.req.get_headers()['Existing-Header']
       assert.same({ 'request_value_eh1', 'request_value_eh2', 'config_value_eh' },
                   ngx.req.get_headers()['Existing-Header'])
       ngx.say('yay, api backend');
     }
  }
--- request
GET /?user_key=value
--- more_headers
Existing-Header: request_value_eh1
Existing-Header: request_value_eh2
--- response_body
yay, api backend
--- response_headers
New-Header:
Existing-Header:
--- error_code: 200
--- no_error_log
[error]

=== TEST 3: 'add' operation in request headers
We test 3 things:
1) Add op with a header that does not exist, does not change anything.
2) Add op with a header that exists, adds a new header with the same name and
   the given value.
3) Check that the headers are received in the upstream but not in the response
   of the original request.
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
            "name": "apicast.policy.headers",
            "configuration":
              {
                "request":
                  [
                    { "op": "add", "header": "New-Header", "value": "config_value_nh" },
                    { "op": "add", "header": "Existing-Header", "value": "config_value_eh" }
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
       assert.is_nil(ngx.req.get_headers()['New-Header'])
       local existing_header_values = ngx.req.get_headers()['Existing-Header']
       assert.same({ 'request_value_eh1', 'request_value_eh2', 'config_value_eh' },
                   ngx.req.get_headers()['Existing-Header'])
       ngx.say('yay, api backend');
     }
  }
--- request
GET /?user_key=value
--- more_headers
Existing-Header: request_value_eh1
Existing-Header: request_value_eh2
--- response_body
yay, api backend
--- response_headers
Existing-Header:
--- error_code: 200
--- no_error_log
[error]

=== TEST 4: 'delete' operation in request headers
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
            "name": "apicast.policy.headers",
            "configuration":
              {
                "request":
                  [
                    { "op": "delete", "header": "Non-Existing-Header" },
                    { "op": "delete", "header": "Existing-Header" }
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
       assert.is_nil(ngx.req.get_headers()['Existing-Header'])
       local header_not_to_be_deleted = ngx.req.get_headers()['Header-Not-To-Be-Deleted']
       assert.same('another_value', header_not_to_be_deleted)
       ngx.say('yay, api backend');
     }
  }
--- request
GET /?user_key=value
--- more_headers
Existing-Header: some_value
Header-Not-To-Be-Deleted: another_value
--- response_body
yay, api backend
--- response_headers
Existing-Header:
Header-Not-To-Be-Deleted:
--- error_code: 200
--- no_error_log
[error]

=== TEST 5: 'set' operation in response headers
We test 3 things:
1) Set op with a header that does not exit creates it with the given value.
2) Set op with a header that exists, clears it and sets the given value.
3) Set op with an empty value clears the header.
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
            "name": "apicast.policy.headers",
            "configuration":
              {
                "response":
                  [
                    { "op": "set", "header": "New-Header", "value": "config_value_nh" },
                    { "op": "set", "header": "Existing-Header", "value": "config_value_eh" },
                    { "op": "set", "header": "Header-To-Delete", "value": "" }
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
       ngx.header['Existing-Header'] = 'upstream_value_eh1, upstream_value_eh2'
       ngx.header['Header-To-Delete'] = 'upstream_value_htd'
       ngx.say('yay, api backend')
     }
  }
--- request
GET /?user_key=value
--- response_body
yay, api backend
--- response_headers
New-Header: config_value_nh
Existing-Header: config_value_eh
Header-To-Delete:
--- error_code: 200
--- no_error_log
[error]

=== TEST 6: 'push' operation in response headers
We test 2 things:
1) Push op with a header that does not exist creates it with the given value.
2) Push op with a header that exists, creates a new header with the same name
   and the given value.
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
            "name": "apicast.policy.headers",
            "configuration":
              {
                "response":
                  [
                    { "op": "push", "header": "New-Header", "value": "config_value_nh" },
                    { "op": "push", "header": "Existing-Header", "value": "config_value_eh" }
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
       ngx.header['Existing-Header'] = 'upstream_value_eh'
       ngx.say('yay, api backend')
     }
  }
--- request
GET /?user_key=value
--- response_body
yay, api backend
--- response_headers
New-Header: config_value_nh
Existing-Header: upstream_value_eh, config_value_eh
Header-To-Delete:
--- error_code: 200
--- no_error_log
[error]

=== TEST 7: 'add' operation in response headers
We test 3 things:
1) Add op with a header that does not exist, does not change anything.
2) Add op with a header that exists, adds a new header with the same name and
   the given value.
3) Check that the headers are received in the upstream but not in the response
   of the original request.
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
            "name": "apicast.policy.headers",
            "configuration":
              {
                "response":
                  [
                    { "op": "add", "header": "New-Header", "value": "config_value_nh" },
                    { "op": "add", "header": "Existing-Header", "value": "config_value_eh" }
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
       ngx.header['Existing-Header'] = 'upstream_value_eh'
       ngx.say('yay, api backend')
     }
  }
--- request
GET /?user_key=value
--- response_body
yay, api backend
--- response_headers
Existing-Header: upstream_value_eh, config_value_eh
New-Header:
--- error_code: 200
--- no_error_log
[error]

=== TEST 8: 'delete' operation in response headers
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
            "name": "apicast.policy.headers",
            "configuration":
              {
                "response":
                  [
                    { "op": "delete", "header": "Header-Set-In-Upstream" },
                    { "op": "delete", "header": "Non-Existing-Header" }
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
       ngx.header['Header-Set-In-Upstream'] = 'upstream_value'
       ngx.say('yay, api backend')
     }
  }
--- request
GET /?user_key=value
--- response_body
yay, api backend
--- response_headers
Header-Set-In-Upstream:
Non-Existing-Header:
--- error_code: 200
--- no_error_log
[error]

=== TEST 9: headers policy without a configuration
Just to make sure that APIcast does not crash when the policy does not have a
configuration.
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
          { "name": "apicast.policy.headers" }
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
GET /?user_key=value
--- more_headers
Some-Header: something
--- response_body
yay, api backend
--- error_code: 200
--- no_error_log
[error]

=== TEST 10: config with liquid templating
Test that we can apply filters and also get values from the policies context
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
            "name": "apicast.policy.headers",
            "configuration":
              {
                "request":
                  [
                    {
                      "op": "set",
                      "header": "New-Header-1",
                      "value": "{{ 'something' | md5 }}",
                      "value_type": "liquid"
                    },
                    {
                      "op": "set",
                      "header": "New-Header-2",
                      "value": "{{ service.id }}",
                      "value_type": "liquid"
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
       assert.same(ngx.md5("something"), ngx.req.get_headers()['New-Header-1'])
       assert.same('42', ngx.req.get_headers()['New-Header-2'])
       ngx.say('yay, api backend');
     }
  }
--- request
GET /?user_key=value
--- response_body
yay, api backend
--- error_code: 200
--- no_error_log
[error]

=== TEST 11: templating with jwt token information
This tests that the headers policy can send headers with jwt information.
The APIcast policy stores the jwt in the policies context, so the headers
policy has access to it.
Notice that in the configuration, oidc.config.public_key is the one in
"/fixtures/rsa.pub".
--- backend
  location /transactions/oauth_authrep.xml {
    content_by_lua_block {
      ngx.exit(200)
    }
  }
--- configuration
{
  "oidc": [
    {
      "issuer": "https://example.com/auth/realms/apicast",
      "config": { "id_token_signing_alg_values_supported": [ "RS256" ] },
      "keys": { "somekid": { "pem": "-----BEGIN PUBLIC KEY-----\nMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALClz96cDQ965ENYMfZzG+Acu25lpx2K\nNpAALBQ+catCA59us7+uLY5rjQR6SOgZpCz5PJiKNAdRPDJMXSmXqM0CAwEAAQ==\n-----END PUBLIC KEY-----" } }
    }
  ],
  "services": [
    {
      "id": 42,
      "backend_version": "oauth",
      "backend_authentication_type": "service_token",
      "backend_authentication_value": "token-value",
      "proxy": {
        "authentication_method": "oidc",
        "oidc_issuer_endpoint": "https://example.com/auth/realms/apicast",
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/",
        "proxy_rules": [
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 2 }
        ],
        "policy_chain": [
          { "name": "apicast.policy.apicast" },
          {
            "name": "apicast.policy.headers",
            "configuration":
              {
                "request":
                  [
                    {
                      "op": "set",
                      "header": "Token-aud",
                      "value": "{{ jwt.aud }}",
                      "value_type": "liquid"
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
       assert.same("the_token_audience", ngx.req.get_headers()['Token-aud'])
       ngx.say('yay, api backend');
     }
  }
--- request
GET /
--- more_headers eval
use Crypt::JWT qw(encode_jwt);
my $jwt = encode_jwt(payload => {
  aud => 'the_token_audience',
  sub => 'someone',
  iss => 'https://example.com/auth/realms/apicast',
  exp => time + 3600 }, key => \$::rsa, alg => 'RS256', extra_headers=>{ kid => 'somekid' });
"Authorization: Bearer $jwt"
--- error_code: 200
--- response_body
yay, api backend
--- no_error_log
[error]
oauth failed with

=== TEST 12: Liquid validate capture works
Validate that capture function works correctly THREESCALE-1911
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
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 2 }
        ],
        "policy_chain": [
          { "name": "apicast.policy.apicast" },
          {
            "name": "apicast.policy.headers",
            "configuration":
              {
                "request":
                  [
                    {
                      "op": "set",
                      "header": "New-Header-1",
                      "value": "{% capture foo%}bar{% endcapture%}{{foo}}",
                      "value_type": "liquid"
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
       assert.same("bar", ngx.req.get_headers()['New-Header-1'])
       ngx.say('yay, api backend');
     }
  }
--- request
GET /?user_key=value
--- response_body
yay, api backend
--- error_code: 200
--- no_error_log
[error]
