use lib 't';
use Test::APIcast::Blackbox 'no_plan';
use Cwd qw(abs_path);
our $rsa = `cat t/fixtures/rsa.pem`;

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
      "config": {
        "public_key": "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALClz96cDQ965ENYMfZzG+Acu25lpx2KNpAALBQ+catCA59us7+uLY5rjQR6SOgZpCz5PJiKNAdRPDJMXSmXqM0CAwEAAQ==",
        "openid": { "id_token_signing_alg_values_supported": [ "RS256" ] }
      }
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
use Crypt::JWT qw(encode_jwt);
my $jwt = encode_jwt(payload => {
  aud => 'the_token_audience',
  nbf => 0,
  iss => 'https://example.com/auth/realms/apicast',
  exp => time + 3600,
  realm_access => {
    roles => [ 'director' ]
  }
}, key => \$::rsa, alg => 'RS256');
"Authorization: Bearer $jwt"
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
      "config": {
        "public_key": "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALClz96cDQ965ENYMfZzG+Acu25lpx2KNpAALBQ+catCA59us7+uLY5rjQR6SOgZpCz5PJiKNAdRPDJMXSmXqM0CAwEAAQ==",
        "openid": { "id_token_signing_alg_values_supported": [ "RS256" ] }
      }
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
use Crypt::JWT qw(encode_jwt);
my $jwt = encode_jwt(payload => {
  aud => 'the_token_audience',
  nbf => 0,
  iss => 'https://example.com/auth/realms/apicast',
  exp => time + 3600,
  resource_access => {
    bank_A => {
      roles => [ 'director' ]
    }
  }
}, key => \$::rsa, alg => 'RS256');
"Authorization: Bearer $jwt"
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
      "config": {
        "public_key": "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALClz96cDQ965ENYMfZzG+Acu25lpx2KNpAALBQ+catCA59us7+uLY5rjQR6SOgZpCz5PJiKNAdRPDJMXSmXqM0CAwEAAQ==",
        "openid": { "id_token_signing_alg_values_supported": [ "RS256" ] }
      }
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
use Crypt::JWT qw(encode_jwt);
my $jwt = encode_jwt(payload => {
  aud => 'the_token_audience',
  nbf => 0,
  iss => 'https://example.com/auth/realms/apicast',
  exp => time + 3600,
  realm_access => {
    roles => [ 'employee' ]
  }
}, key => \$::rsa, alg => 'RS256');
"Authorization: Bearer $jwt"
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
      "config": {
        "public_key": "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALClz96cDQ965ENYMfZzG+Acu25lpx2KNpAALBQ+catCA59us7+uLY5rjQR6SOgZpCz5PJiKNAdRPDJMXSmXqM0CAwEAAQ==",
        "openid": { "id_token_signing_alg_values_supported": [ "RS256" ] }
      }
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
use Crypt::JWT qw(encode_jwt);
my $jwt = encode_jwt(payload => {
  aud => 'the_token_audience',
  nbf => 0,
  iss => 'https://example.com/auth/realms/apicast',
  exp => time + 3600,
  resource_access => {
    bank_A => {
      roles => [ 'employee' ]
    }
  }
}, key => \$::rsa, alg => 'RS256');
"Authorization: Bearer $jwt"
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
      "config": {
        "public_key": "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALClz96cDQ965ENYMfZzG+Acu25lpx2KNpAALBQ+catCA59us7+uLY5rjQR6SOgZpCz5PJiKNAdRPDJMXSmXqM0CAwEAAQ==",
        "openid": { "id_token_signing_alg_values_supported": [ "RS256" ] }
      }
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
use Crypt::JWT qw(encode_jwt);
my $jwt = encode_jwt(payload => {
  aud => 'app1',
  nbf => 0,
  iss => 'https://example.com/auth/realms/apicast',
  exp => time + 3600,
  resource_access => {
    app1 => {
      roles => [ 'app1' ]
    }
  }
}, key => \$::rsa, alg => 'RS256');
"Authorization: Bearer $jwt"
--- error_code: 200
--- response_body
yay, api backend
--- no_error_log
[error]
oauth failed with
