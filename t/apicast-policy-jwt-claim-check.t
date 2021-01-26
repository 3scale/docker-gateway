use lib 't';
use Test::APIcast::Blackbox 'no_plan';
use Crypt::JWT qw(encode_jwt);

my $rsa = `cat t/fixtures/rsa.pem`;

sub authorization_bearer_jwt (@) {
    my ($aud, $payload, $kid) = @_;

    my $jwt = encode_jwt(payload => {
        aud => $aud,
        sub => 'someone',
        iss => 'https://example.com/auth/realms/apicast',
        exp => time + 3600,
        %$payload,
    }, key => \$rsa, alg => 'RS256', extra_headers => { kid => $kid });

    return "Authorization: Bearer $jwt";
}

run_tests();

__DATA__

=== TEST 1: JWT claim plain match type
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
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 1 }
        ],
        "policy_chain": [
          {
            "name": "apicast.policy.jwt_claim_check",
            "configuration": {
              "rules" : [{
                  "operations": [
                      {"op": "==", "jwt_claim": "foo", "jwt_claim_type": "plain", "value": "1"}
                  ],
                  "combine_op": "and",
                  "methods": ["GET"],
                  "resource": "/confidential"
              }]
            }
          },
          { "name": "apicast.policy.apicast" }
        ]
      }
    }
  ]
}
--- upstream
  location /confidential {
     content_by_lua_block {
       ngx.say('yay, api backend');
     }
  }
--- request
GET /confidential
--- more_headers eval
::authorization_bearer_jwt('audience', {
  realm_access => {
    roles => [ 'director' ]
  },
  foo => "1",
}, 'somekid')
--- error_code: 200
--- response_body
yay, api backend
--- no_error_log
[error]

=== TEST 2: JWT claim liquid match type
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
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 1 }
        ],
        "policy_chain": [
          {
            "name": "apicast.policy.jwt_claim_check",
            "configuration": {
              "rules" : [{
                  "operations": [
                      {"op": "==", "jwt_claim": "{{foo}}", "jwt_claim_type": "liquid", "value": "1"}
                  ],
                  "combine_op": "and",
                  "methods": ["GET"],
                  "resource": "/confidential"
              }]
            }
          },
          { "name": "apicast.policy.apicast" }
        ]
      }
    }
  ]
}
--- upstream
  location /confidential {
     content_by_lua_block {
       ngx.say('yay, api backend');
     }
  }
--- request
GET /confidential
--- more_headers eval
::authorization_bearer_jwt('audience', {
  foo => "1",
}, 'somekid')
--- error_code: 200
--- response_body
yay, api backend
--- no_error_log
[error]

=== TEST 3: JWT claim with multiple rules
Rule where whitelist and blacklist operations are tested that works as expected
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
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 1 }
        ],
        "policy_chain": [
          {
            "name": "apicast.policy.jwt_claim_check",
            "configuration": {
              "rules" : [{
                  "operations": [
                    {"op": "==", "jwt_claim": "{{foo}}", "jwt_claim_type": "liquid", "value": "1"},
                    {"op": "!=", "jwt_claim": "{{bar}}", "jwt_claim_type": "liquid", "value": "2"},
                    {"op": "==", "jwt_claim": "{{roles| first}}", "jwt_claim_type": "liquid", "value": "director"}
                  ],
                  "combine_op": "and",
                  "methods": ["GET"],
                  "resource": "/confidential"
              }]
            }
          },
          { "name": "apicast.policy.apicast" }
        ]
      }
    }
  ]
}
--- upstream
  location /confidential {
     content_by_lua_block {
       ngx.say('yay, api backend');
     }
  }
--- request
GET /confidential
--- more_headers eval
::authorization_bearer_jwt('audience', {
  foo => "1",
  bar => "1",
  roles => [ 'director', 'manager' ]
}, 'somekid')
--- error_code: 200
--- response_body
yay, api backend
--- no_error_log
[error]

=== TEST 4: JWT claim with multiple rules only one match.
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
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 1 }
        ],
        "policy_chain": [
          {
            "name": "apicast.policy.jwt_claim_check",
            "configuration": {
              "rules" : [{
                  "operations": [
                    {"op": "!=", "jwt_claim": "{{bar}}", "jwt_claim_type": "liquid", "value": "2"},
                    {"op": "==", "jwt_claim": "{{roles| first}}", "jwt_claim_type": "liquid", "value": "CEO"},
                    {"op": "==", "jwt_claim": "{{foo}}", "jwt_claim_type": "liquid", "value": "1"}
                  ],
                  "combine_op": "or",
                  "methods": ["GET"],
                  "resource": "/confidential"
              }]
            }
          },
          { "name": "apicast.policy.apicast" }
        ]
      }
    }
  ]
}
--- upstream
  location /confidential {
     content_by_lua_block {
       ngx.say('yay, api backend');
     }
  }
--- request
GET /confidential
--- more_headers eval
::authorization_bearer_jwt('audience', {
  foo => "1",
  bar => "1",
  roles => [ 'director', 'manager' ]
}, 'somekid')
--- error_code: 200
--- response_body
yay, api backend
--- no_error_log
[error]


=== TEST 5: custom error message
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
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 1 }
        ],
        "policy_chain": [
          {
            "name": "apicast.policy.jwt_claim_check",
            "configuration": {
              "error_message": "JWT no valid",
              "rules" : [{
                  "operations": [
                    {"op": "==", "jwt_claim": "{{foo}}", "jwt_claim_type": "liquid", "value": "2"}
                  ],
                  "combine_op": "and",
                  "methods": ["GET"],
                  "resource": "/confidential"
              }]
            }
          },
          { "name": "apicast.policy.apicast" }
        ]
      }
    }
  ]
}
--- upstream
  location /confidential {
     content_by_lua_block {
       ngx.say('yay, api backend');
     }
  }
--- request
GET /confidential
--- more_headers eval
::authorization_bearer_jwt('audience', {
  foo => "1",
}, 'somekid')
--- error_code: 403
--- response_body
JWT no valid
--- no_error_log
[error]

=== TEST 6: JWT claim with liquid value.
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
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 1 }
        ],
        "policy_chain": [
          {
            "name": "apicast.policy.jwt_claim_check",
            "configuration": {
              "rules" : [{
                  "operations": [
                    {"op": "!=", "jwt_claim": "{{foo}}", "jwt_claim_type": "liquid", "value": "test_{{foo}}", "value_type": "liquid"}
                  ],
                  "combine_op": "and",
                  "methods": ["GET"],
                  "resource": "/confidential"
              }]
            }
          },
          { "name": "apicast.policy.apicast" }
        ]
      }
    }
  ]
}
--- upstream
  location /confidential {
     content_by_lua_block {
       ngx.say('yay, api backend');
     }
  }
--- request
GET /confidential
--- more_headers eval
::authorization_bearer_jwt('audience', {
  foo => "test_foo",
  bar => "foo",
  roles => [ 'director', 'manager' ]
}, 'somekid')
--- error_code: 200
--- response_body
yay, api backend
--- no_error_log
[error]


=== TEST 7: JWT claim with routing policy uri change
When using the routing policy, the set_uri is in use, and moved to /, so the
the URI is not longer valid at all, and JWT is not expected to work correctly.
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
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 1 }
        ],
        "policy_chain": [
          {
            "name": "apicast.policy.routing",
            "configuration": {
              "rules": [
                {
                  "url": "http://test:$TEST_NGINX_SERVER_PORT",
                  "replace_path": "{{original_request.path }}-test",
                  "condition": {
                    "operations": [
                      {
                        "match": "liquid",
                        "liquid_value": "/confidential",
                        "op": "==",
                        "value": "/confidential"
                      }
                    ]
                  }
                }
              ]
            }
          },
          {
            "name": "apicast.policy.jwt_claim_check",
            "configuration": {
              "rules" : [
                {
                  "operations": [
                    {"op": "==", "jwt_claim": "{{foo}}", "jwt_claim_type": "liquid", "value": "test_foo", "value_type": "liquid"}
                  ],
                  "combine_op": "and",
                  "methods": ["GET"],
                  "resource": "/confidential"
                },
                {
                  "operations": [
                    {"op": "==", "jwt_claim": "{{foo}}", "jwt_claim_type": "liquid", "value": "INVALID", "value_type": "liquid"}
                  ],
                  "combine_op": "and",
                  "methods": ["GET"],
                  "resource": "/test.*"
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
  location /confidential {
     content_by_lua_block {
       ngx.say('yay, api backend');
     }
  }

  location /test {
     content_by_lua_block {
       ngx.say('yay, api backend');
     }
  }

--- request eval
["GET /confidential", "GET /test"]
--- more_headers eval
[
::authorization_bearer_jwt('audience', {
  foo => "test_foo",
  bar => "foo",
  roles => [ 'director', 'manager' ]
}, 'somekid'),
::authorization_bearer_jwt('audience', {
  foo => "test_foo",
  bar => "foo",
  roles => [ 'director', 'manager' ]
}, 'somekid')
]
--- error_code eval
[200, 403]
--- response_body eval
["yay, api backend\n","Request blocked due to JWT claim policy\n"]
--- no_error_log
[error]
