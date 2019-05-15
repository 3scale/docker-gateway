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

=== TEST1: Role check succeeds (whitelist)
The client which has the appropriate role accesses the resource.
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
            "name": "apicast.policy.keycloak_role_check",
            "configuration": {
              "scopes": [
                {
                  "realm_roles": [ { "name": "director" } ],
                  "resource": "/confidential"
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
--- request
GET /confidential
--- more_headers eval
::authorization_bearer_jwt('audience', {
  realm_access => {
    roles => [ 'director' ]
  }
}, 'somekid')
--- error_code: 200
--- response_body
yay, api backend
--- no_error_log
[error]
oauth failed with



=== TEST2: Role check succeeds (blacklist)
The client which doesn't have the inappropriate role accesses the resource.
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
            "name": "apicast.policy.keycloak_role_check",
            "configuration": {
              "scopes": [
                {
                  "client_roles": [ { "name": "employee", "client": "bank_A" } ],
                  "resource": "/confidential"
                }
              ],
              "type": "blacklist"
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
  resource_access => {
    bank_A => {
      roles => [ 'director' ]
    }
  }
}, 'somekid');
--- error_code: 200
--- response_body
yay, api backend
--- no_error_log
[error]
oauth failed with



=== TEST3: Role check fails (whitelist)
The client which doesn't have the appropriate role accesses the resource.
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
        "error_status_auth_failed": 403,
        "error_auth_failed": "auth failed",
        "oidc_issuer_endpoint": "https://example.com/auth/realms/apicast",
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/",
        "proxy_rules": [
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 1 }
        ],
        "policy_chain": [
          {
            "name": "apicast.policy.keycloak_role_check",
            "configuration": {
              "scopes": [
                {
                  "realm_roles": [ { "name": "director" } ],
                  "resource": "/confidential"
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
--- request
GET /confidential
--- more_headers eval
::authorization_bearer_jwt('audience', {
  realm_access => {
    roles => [ 'employee' ]
  }
}, 'somekid')
--- error_code: 403
--- response_body chomp
auth failed



=== TEST4: Role check fails (blacklist)
The client which has the inappropriate role accesses the resource.
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
        "error_status_auth_failed": 403,
        "error_auth_failed": "auth failed",
        "oidc_issuer_endpoint": "https://example.com/auth/realms/apicast",
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/",
        "proxy_rules": [
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 1 }
        ],
        "policy_chain": [
          {
            "name": "apicast.policy.keycloak_role_check",
            "configuration": {
              "scopes": [
                {
                  "client_roles": [ { "name": "employee", "client": "bank_A" } ],
                  "resource": "/confidential"
                }
              ],
              "type": "blacklist"
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
  resource_access => {
    bank_A => {
      roles => [ 'employee' ]
    }
  }
}, 'somekid')
--- error_code: 403
--- response_body chomp
auth failed



=== TEST5: Role check succeeds with Liquid template (whitelist)
The client which has the appropriate role accesses the resource.
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
            "name": "apicast.policy.keycloak_role_check",
            "configuration": {
              "scopes": [
                {
                  "client_roles": [
                    {
                      "name": "{{ jwt.aud }}",
                      "name_type": "liquid",
                      "client": "{{ jwt.aud }}",
                      "client_type": "liquid"
                    }
                  ],
                  "resource": "/{{ jwt.aud }}",
                  "resource_type": "liquid"
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
  location /app1 {
     content_by_lua_block {
       ngx.say('yay, api backend');
     }
  }
--- request
GET /app1
--- more_headers eval
::authorization_bearer_jwt('app1', {
  resource_access => {
    app1 => {
      roles => [ 'app1' ]
    }
  }
}, 'somekid')
--- error_code: 200
--- response_body
yay, api backend
--- no_error_log
[error]
oauth failed with


=== TEST6: Role check with allow methods
The client which has the appropriate role accesses the resource with only one method allowed
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
            "name": "apicast.policy.keycloak_role_check",
            "configuration": {
              "scopes": [
                {
                  "realm_roles": [ { "name": "director" } ],
                  "resource": "/confidential",
                  "methods": ["GET"]
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
--- pipelined_requests eval
["GET /confidential", "POST /confidential"]
--- more_headers eval
[::authorization_bearer_jwt('audience', {
  realm_access => {
    roles => [ 'director' ]
  }
}, 'somekid'),
::authorization_bearer_jwt('audience', {
  realm_access => {
    roles => [ 'director' ]
  }
}, 'somekid')]
--- response_body eval
["yay, api backend\n", "Authentication failed"]
--- error_code eval
[200, 403]
--- no_error_log
[error]
oauth failed with


=== TEST7: Role check with allow methods and blacklist mode
Check an allowed role with the blacklisted mode with methods
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
            "name": "apicast.policy.keycloak_role_check",
            "configuration": {
              "scopes": [
                {
                  "realm_roles": [ { "name": "director" } ],
                  "resource": "/confidential",
                  "methods": ["POST"]
                }
              ],
              "type": "blacklist"
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
--- pipelined_requests eval
["GET /confidential", "POST /confidential"]
--- more_headers eval
[::authorization_bearer_jwt('audience', {
  realm_access => {
    roles => [ 'director' ]
  }
}, 'somekid'),
::authorization_bearer_jwt('audience', {
  realm_access => {
    roles => [ 'director' ]
  }
}, 'somekid')]
--- response_body eval
["yay, api backend\n", "Authentication failed"]
--- error_code eval
[200, 403]
--- no_error_log
[error]
oauth failed with
