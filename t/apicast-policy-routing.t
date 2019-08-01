use lib 't';
use Test::APIcast::Blackbox 'no_plan';

our $rsa = `cat t/fixtures/rsa.pem`;

run_tests();

__DATA__

=== TEST 1: the rule matches the path using "=="
--- configuration
{
  "services": [
    {
      "id": 42,
      "proxy": {
        "policy_chain": [
          {
            "name": "apicast.policy.routing",
            "configuration": {
              "rules": [
                {
                  "url": "http://test:$TEST_NGINX_SERVER_PORT",
                  "condition": {
                    "operations": [
                      {
                        "match": "path",
                        "op": "==",
                        "value": "/a_path"
                      }
                    ]
                  }
                }
              ]
            }
          },
          {
            "name": "apicast.policy.echo"
          }
        ]
      }
    }
  ]
}
--- upstream
  location /a_path {
     content_by_lua_block {
       ngx.say('yay, api backend');
     }
  }
--- request
GET /a_path
--- response_body
yay, api backend
--- error_code: 200
--- no_error_log
[error]

=== TEST 2: the rule matches the path using "!="
--- configuration
{
  "services": [
    {
      "id": 42,
      "proxy": {
        "policy_chain": [
          {
            "name": "apicast.policy.routing",
            "configuration": {
              "rules": [
                {
                  "url": "http://test:$TEST_NGINX_SERVER_PORT",
                  "condition": {
                    "operations": [
                      {
                        "match": "path",
                        "op": "!=",
                        "value": "/"
                      }
                    ]
                  }
                }
              ]
            }
          },
          {
            "name": "apicast.policy.echo"
          }
        ]
      }
    }
  ]
}
--- upstream
  location /i_dont_match {
     content_by_lua_block {
       ngx.say('yay, api backend');
     }
  }
--- request
GET /i_dont_match
--- response_body
yay, api backend
--- error_code: 200
--- no_error_log
[error]

=== TEST 3: the rule matches the path using "matches"
--- configuration
{
  "services": [
    {
      "id": 42,
      "proxy": {
        "policy_chain": [
          {
            "name": "apicast.policy.routing",
            "configuration": {
              "rules": [
                {
                  "url": "http://test:$TEST_NGINX_SERVER_PORT",
                  "condition": {
                    "operations": [
                      {
                        "match": "path",
                        "op": "matches",
                        "value": ".*123.*"
                      }
                    ]
                  }
                }
              ]
            }
          },
          {
            "name": "apicast.policy.echo"
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
GET /something_123_something
--- response_body
yay, api backend
--- error_code: 200
--- no_error_log
[error]

=== TEST 4: the rule matches a header using "=="
--- configuration
{
  "services": [
    {
      "id": 42,
      "proxy": {
        "policy_chain": [
          {
            "name": "apicast.policy.routing",
            "configuration": {
              "rules": [
                {
                  "url": "http://test:$TEST_NGINX_SERVER_PORT",
                  "condition": {
                    "operations": [
                      {
                        "match": "header",
                        "header_name": "Test-Header",
                        "op": "==",
                        "value": "some_value"
                      }
                    ]
                  }
                }
              ]
            }
          },
          {
            "name": "apicast.policy.echo"
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
--- more_headers
Test-Header: some_value
--- response_body
yay, api backend
--- error_code: 200
--- no_error_log
[error]

=== TEST 5: the rule matches a header using "!="
--- configuration
{
  "services": [
    {
      "id": 42,
      "proxy": {
        "policy_chain": [
          {
            "name": "apicast.policy.routing",
            "configuration": {
              "rules": [
                {
                  "url": "http://test:$TEST_NGINX_SERVER_PORT",
                  "condition": {
                    "operations": [
                      {
                        "match": "header",
                        "header_name": "Test-Header",
                        "op": "!=",
                        "value": "some_value"
                      }
                    ]
                  }
                }
              ]
            }
          },
          {
            "name": "apicast.policy.echo"
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
--- more_headers
Test-Header: i_dont_match
--- response_body
yay, api backend
--- error_code: 200
--- no_error_log
[error]

=== TEST 6: the rule matches a header using "matches"
--- configuration
{
  "services": [
    {
      "id": 42,
      "proxy": {
        "policy_chain": [
          {
            "name": "apicast.policy.routing",
            "configuration": {
              "rules": [
                {
                  "url": "http://test:$TEST_NGINX_SERVER_PORT",
                  "condition": {
                    "operations": [
                      {
                        "match": "header",
                        "header_name": "Test-Header",
                        "op": "matches",
                        "value": ".*123.*"
                      }
                    ]
                  }
                }
              ]
            }
          },
          {
            "name": "apicast.policy.echo"
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
--- more_headers
Test-Header: something_123_something
--- response_body
yay, api backend
--- error_code: 200
--- no_error_log
[error]

=== TEST 7: the rule matches a query arg using "=="
--- configuration
{
  "services": [
    {
      "id": 42,
      "proxy": {
        "policy_chain": [
          {
            "name": "apicast.policy.routing",
            "configuration": {
              "rules": [
                {
                  "url": "http://test:$TEST_NGINX_SERVER_PORT",
                  "condition": {
                    "operations": [
                      {
                        "match": "query_arg",
                        "query_arg_name": "test_arg",
                        "op": "==",
                        "value": "some_value"
                      }
                    ]
                  }
                }
              ]
            }
          },
          {
            "name": "apicast.policy.echo"
          }
        ]
      }
    }
  ]
}
--- upstream
  location /a_path {
     content_by_lua_block {
       ngx.say('yay, api backend');
     }
  }
--- request
GET /a_path?test_arg=some_value
--- response_body
yay, api backend
--- error_code: 200
--- no_error_log
[error]

=== TEST 8: the rule matches a query arg using "!="
--- configuration
{
  "services": [
    {
      "id": 42,
      "proxy": {
        "policy_chain": [
          {
            "name": "apicast.policy.routing",
            "configuration": {
              "rules": [
                {
                  "url": "http://test:$TEST_NGINX_SERVER_PORT",
                  "condition": {
                    "operations": [
                      {
                        "match": "query_arg",
                        "query_arg_name": "test_arg",
                        "op": "!=",
                        "value": "some_value"
                      }
                    ]
                  }
                }
              ]
            }
          },
          {
            "name": "apicast.policy.echo"
          }
        ]
      }
    }
  ]
}
--- upstream
  location /a_path {
     content_by_lua_block {
       ngx.say('yay, api backend');
     }
  }
--- request
GET /a_path?test_arg=i_dont_match
--- response_body
yay, api backend
--- error_code: 200
--- no_error_log
[error]

=== TEST 9: the rule matches a query arg using "matches"
--- configuration
{
  "services": [
    {
      "id": 42,
      "proxy": {
        "policy_chain": [
          {
            "name": "apicast.policy.routing",
            "configuration": {
              "rules": [
                {
                  "url": "http://test:$TEST_NGINX_SERVER_PORT",
                  "condition": {
                    "operations": [
                      {
                        "match": "query_arg",
                        "query_arg_name": "test_arg",
                        "op": "matches",
                        "value": ".*123.*"
                      }
                    ]
                  }
                }
              ]
            }
          },
          {
            "name": "apicast.policy.echo"
          }
        ]
      }
    }
  ]
}
--- upstream
  location /a_path {
     content_by_lua_block {
       ngx.say('yay, api backend');
     }
  }
--- request
GET /a_path?test_arg=something_123_something
--- response_body
yay, api backend
--- error_code: 200
--- no_error_log
[error]

=== TEST 10: the rule matches a jwt claim using "=="
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
        "id_token_signing_alg_values_supported": [
          "RS256"
        ]
      },
      "keys": {
        "somekid": {
          "pem": "-----BEGIN PUBLIC KEY-----\nMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALClz96cDQ965ENYMfZzG+Acu25lpx2K\nNpAALBQ+catCA59us7+uLY5rjQR6SOgZpCz5PJiKNAdRPDJMXSmXqM0CAwEAAQ==\n-----END PUBLIC KEY-----"
        }
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
        "api_backend": "http://example.com:80/",
        "proxy_rules": [
          {
            "pattern": "/",
            "http_method": "GET",
            "metric_system_name": "hits",
            "delta": 2
          }
        ],
        "policy_chain": [
          {
            "name": "apicast.policy.routing",
            "configuration": {
              "rules": [
                {
                  "url": "http://test:$TEST_NGINX_SERVER_PORT",
                  "condition": {
                    "operations": [
                      {
                        "match": "jwt_claim",
                        "jwt_claim_name": "test_jwt_claim",
                        "op": "==",
                        "value": "some_value"
                      }
                    ]
                  }
                }
              ]
            }
          },
          {
            "name": "apicast.policy.echo"
          },
          {
            "name": "apicast.policy.apicast"
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
--- more_headers eval
use Crypt::JWT qw(encode_jwt);
my $jwt = encode_jwt(payload => {
test_jwt_claim => 'some_value',
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

=== TEST 11: the rule matches a jwt claim using "!="
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
        "id_token_signing_alg_values_supported": [
          "RS256"
        ]
      },
      "keys": {
        "somekid": {
          "pem": "-----BEGIN PUBLIC KEY-----\nMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALClz96cDQ965ENYMfZzG+Acu25lpx2K\nNpAALBQ+catCA59us7+uLY5rjQR6SOgZpCz5PJiKNAdRPDJMXSmXqM0CAwEAAQ==\n-----END PUBLIC KEY-----"
        }
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
        "api_backend": "http://example.com:80/",
        "proxy_rules": [
          {
            "pattern": "/",
            "http_method": "GET",
            "metric_system_name": "hits",
            "delta": 2
          }
        ],
        "policy_chain": [
          {
            "name": "apicast.policy.routing",
            "configuration": {
              "rules": [
                {
                  "url": "http://test:$TEST_NGINX_SERVER_PORT",
                  "condition": {
                    "operations": [
                      {
                        "match": "jwt_claim",
                        "jwt_claim_name": "test_jwt_claim",
                        "op": "!=",
                        "value": "some_value"
                      }
                    ]
                  }
                }
              ]
            }
          },
          {
            "name": "apicast.policy.echo"
          },
          {
            "name": "apicast.policy.apicast"
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
--- more_headers eval
use Crypt::JWT qw(encode_jwt);
my $jwt = encode_jwt(payload => {
test_jwt_claim => 'i_dont_match',
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

=== TEST 12: the rule matches a jwt claim using "matches"
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
        "id_token_signing_alg_values_supported": [
          "RS256"
        ]
      },
      "keys": {
        "somekid": {
          "pem": "-----BEGIN PUBLIC KEY-----\nMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALClz96cDQ965ENYMfZzG+Acu25lpx2K\nNpAALBQ+catCA59us7+uLY5rjQR6SOgZpCz5PJiKNAdRPDJMXSmXqM0CAwEAAQ==\n-----END PUBLIC KEY-----"
        }
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
        "api_backend": "http://example.com:80/",
        "proxy_rules": [
          {
            "pattern": "/",
            "http_method": "GET",
            "metric_system_name": "hits",
            "delta": 2
          }
        ],
        "policy_chain": [
          {
            "name": "apicast.policy.routing",
            "configuration": {
              "rules": [
                {
                  "url": "http://test:$TEST_NGINX_SERVER_PORT",
                  "condition": {
                    "operations": [
                      {
                        "match": "jwt_claim",
                        "jwt_claim_name": "test_jwt_claim",
                        "op": "matches",
                        "value": ".*123.*"
                      }
                    ]
                  }
                }
              ]
            }
          },
          {
            "name": "apicast.policy.echo"
          },
          {
            "name": "apicast.policy.apicast"
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
--- more_headers eval
use Crypt::JWT qw(encode_jwt);
my $jwt = encode_jwt(payload => {
test_jwt_claim => 'something_123_something',
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

=== TEST 13: several matching rules
When there are several rules that match, the upstream selected is the one of
the first rule that matches.
--- configuration
{
  "services": [
    {
      "id": 42,
      "proxy": {
        "policy_chain": [
          {
            "name": "apicast.policy.routing",
            "configuration": {
              "rules": [
                {
                  "url": "http://test:$TEST_NGINX_SERVER_PORT",
                  "condition": {
                    "operations": [
                      {
                        "match": "path",
                        "op": "==",
                        "value": "/a_path"
                      }
                    ]
                  }
                },
                {
                  "url": "http://example.com",
                  "condition": {
                    "operations": [
                      {
                        "match": "path",
                        "op": "==",
                        "value": "/a_path"
                      }
                    ]
                  }
                }
              ]
            }
          },
          {
            "name": "apicast.policy.echo"
          }
        ]
      }
    }
  ]
}
--- upstream
  location /a_path {
     content_by_lua_block {
       ngx.say('yay, api backend');
     }
  }
--- request
GET /a_path
--- more_headers
Test-Header: a_value
--- response_body
yay, api backend
--- error_code: 200
--- no_error_log
[error]

=== TEST 14: upstream with path
The path of the upstream is appended to the path of the request.
--- configuration
{
  "services": [
    {
      "id": 42,
      "proxy": {
        "policy_chain": [
          {
            "name": "apicast.policy.routing",
            "configuration": {
              "rules": [
                {
                  "url": "http://test:$TEST_NGINX_SERVER_PORT/the_path_in_the_rule",
                  "condition": {
                    "operations": [
                      {
                        "match": "path",
                        "op": "==",
                        "value": "/the_request_path"
                      }
                    ]
                  }
                }
              ]
            }
          },
          {
            "name": "apicast.policy.echo"
          }
        ]
      }
    }
  ]
}
--- upstream
  location / {
    echo $request;
  }
--- request
GET /the_request_path
--- more_headers
Test-Header: a_value
--- response_body
GET /the_path_in_the_rule/the_request_path HTTP/1.1
--- error_code: 200
--- no_error_log
[error]

=== TEST 15: entities in the rules are not set
This test checks that when the entities in the rules are not set, the program
does not raise any errors and rules do not match.
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
        "id_token_signing_alg_values_supported": [
          "RS256"
        ]
      },
      "keys": {
        "somekid": {
          "pem": "-----BEGIN PUBLIC KEY-----\nMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALClz96cDQ965ENYMfZzG+Acu25lpx2K\nNpAALBQ+catCA59us7+uLY5rjQR6SOgZpCz5PJiKNAdRPDJMXSmXqM0CAwEAAQ==\n-----END PUBLIC KEY-----"
        }
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
        "api_backend": "http://example.com:80/",
        "proxy_rules": [
          {
            "pattern": "/",
            "http_method": "GET",
            "metric_system_name": "hits",
            "delta": 2
          }
        ],
        "policy_chain": [
          {
            "name": "apicast.policy.routing",
            "configuration": {
              "rules": [
                {
                  "url": "http://test:$TEST_NGINX_SERVER_PORT",
                  "condition": {
                    "operations": [
                      {
                        "match": "header",
                        "header_name": "header_not_in_the_request",
                        "op": "==",
                        "value": "some_value"
                      }
                    ]
                  }
                },
                {
                  "url": "http://test:$TEST_NGINX_SERVER_PORT",
                  "condition": {
                    "operations": [
                      {
                        "match": "query_arg",
                        "query_arg_name": "arg_not_in_the_request",
                        "op": "==",
                        "value": "some_value"
                      }
                    ]
                  }
                },
                {
                  "url": "http://test:$TEST_NGINX_SERVER_PORT",
                  "condition": {
                    "operations": [
                      {
                        "match": "jwt_claim",
                        "jwt_claim_name": "claim_not_in_the_request",
                        "op": "==",
                        "value": "some_value"
                      }
                    ]
                  }
                }
              ]
            }
          },
          {
            "name": "apicast.policy.echo"
          },
          {
            "name": "apicast.policy.apicast"
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
--- more_headers eval
use Crypt::JWT qw(encode_jwt);
my $jwt = encode_jwt(payload => {
test_jwt_claim => 'some_value',
aud => 'the_token_audience',
sub => 'someone',
iss => 'https://example.com/auth/realms/apicast',
exp => time + 3600 }, key => \$::rsa, alg => 'RS256', extra_headers=>{ kid => 'somekid' });
"Authorization: Bearer $jwt"
--- error_code: 200
--- response_body
GET / HTTP/1.1
--- no_error_log
[error]

=== TEST 16: upstream with several operations and all of them are true
When the "combine_op" (and, or) is not set, APIcast defaults to 'and'.
So the condition evaluates to true only when all the operations evaluate to
true as well.
--- configuration
{
  "services": [
    {
      "id": 42,
      "proxy": {
        "policy_chain": [
          {
            "name": "apicast.policy.routing",
            "configuration": {
              "rules": [
                {
                  "url": "http://test:$TEST_NGINX_SERVER_PORT",
                  "condition": {
                    "operations": [
                      {
                        "match": "path",
                        "op": "==",
                        "value": "/a_path"
                      },
                      {
                        "match": "header",
                        "header_name": "Test-Header",
                        "op": "==",
                        "value": "some_value"
                      }
                    ]
                  }
                }
              ]
            }
          },
          {
            "name": "apicast.policy.echo"
          }
        ]
      }
    }
  ]
}
--- upstream
  location /a_path {
     content_by_lua_block {
       ngx.say('yay, api backend');
     }
  }
--- request
GET /a_path
--- more_headers
Test-Header: some_value
--- response_body
yay, api backend
--- error_code: 200
--- no_error_log
[error]

=== TEST 17: upstream with several conditions and some of them are false
When one or more conditions are false, the request is not routed
--- configuration
{
  "services": [
    {
      "id": 42,
      "proxy": {
        "policy_chain": [
          {
            "name": "apicast.policy.routing",
            "configuration": {
              "rules": [
                {
                  "url": "http://test:$TEST_NGINX_SERVER_PORT",
                  "condition": {
                    "operations": [
                      {
                        "match": "path",
                        "op": "==",
                        "value": "/a_path"
                      },
                      {
                        "match": "header",
                        "header_name": "Test-Header",
                        "op": "==",
                        "value": "some_value"
                      }
                    ]
                  }
                }
              ]
            }
          },
          {
            "name": "apicast.policy.echo"
          }
        ]
      }
    }
  ]
}
--- upstream
  location /a_path {
     content_by_lua_block {
       ngx.say('yay, api backend');
     }
  }
--- request
GET /a_path
--- more_headers
Test-Header: i_dont_match
--- response_body
GET /a_path HTTP/1.1
--- error_code: 200
--- no_error_log
[error]

=== TEST 18: conditions combined with 'or'
In this test, we define a rule with two operations that evaluate to false
combined with 'or', and a second rule with two operations combined with 'or'
and only the second operation evaluates to true.
The test checks that the upstream selected is the one of the second rule.
--- configuration
{
  "services": [
    {
      "id": 42,
      "proxy": {
        "policy_chain": [
          {
            "name": "apicast.policy.routing",
            "configuration": {
              "rules": [
                {
                  "url": "http://test:$TEST_NGINX_SERVER_PORT/wrong",
                  "condition": {
                    "combine_op": "or",
                    "operations": [
                      {
                        "match": "path",
                        "op": "==",
                        "value": "/rule_path"
                      },
                      {
                        "match": "header",
                        "header_name": "Test-Header",
                        "op": "==",
                        "value": "rule_header_value"
                      }
                    ]
                  }
                },
                {
                  "url": "http://test:$TEST_NGINX_SERVER_PORT",
                  "condition": {
                    "combine_op": "or",
                    "operations": [
                      {
                        "match": "path",
                        "op": "==",
                        "value": "/rule_path"
                      },
                      {
                        "match": "query_arg",
                        "query_arg_name": "test_arg",
                        "op": "==",
                        "value": "rule_arg_value"
                      }
                    ]
                  }
                }
              ]
            }
          },
          {
            "name": "apicast.policy.echo"
          }
        ]
      }
    }
  ]
}
--- upstream
  location /request_path {
     content_by_lua_block {
       ngx.say('yay, api backend');
     }
  }

  location /wrong {
     content_by_lua_block {
       ngx.status = 403
       ngx.say('Selected wrong upstream');
     }
  }
--- request
GET /request_path?test_arg=rule_arg_value
--- more_headers
Test-Header: i_dont_match
--- response_body
yay, api backend
--- error_code: 200
--- no_error_log
[error]

=== TEST 19: conditions combined with 'and'
In this test, we define a rule with two operations combined with 'and' where
only one of them evaluates to true, and a second rule with two operations
combined with 'and' where both of them evaluate to true.
The test checks that the upstream selected is the one of the second rule.
--- configuration
{
  "services": [
    {
      "id": 42,
      "proxy": {
        "policy_chain": [
          {
            "name": "apicast.policy.routing",
            "configuration": {
              "rules": [
                {
                  "url": "http://test:$TEST_NGINX_SERVER_PORT/wrong",
                  "condition": {
                    "combine_op": "and",
                    "operations": [
                      {
                        "match": "path",
                        "op": "==",
                        "value": "/rule_path"
                      },
                      {
                        "match": "header",
                        "header_name": "Test-Header",
                        "op": "==",
                        "value": "rule_header_value"
                      }
                    ]
                  }
                },
                {
                  "url": "http://test:$TEST_NGINX_SERVER_PORT",
                  "condition": {
                    "combine_op": "and",
                    "operations": [
                      {
                        "match": "path",
                        "op": "==",
                        "value": "/rule_path"
                      },
                      {
                        "match": "query_arg",
                        "query_arg_name": "test_arg",
                        "op": "==",
                        "value": "rule_arg_value"
                      }
                    ]
                  }
                }
              ]
            }
          },
          {
            "name": "apicast.policy.echo"
          }
        ]
      }
    }
  ]
}
--- upstream
  location /rule_path {
     content_by_lua_block {
       ngx.say('yay, api backend');
     }
  }

  location /wrong {
     content_by_lua_block {
       ngx.status = 403
       ngx.say('Selected wrong upstream');
     }
  }
--- request
GET /rule_path?test_arg=rule_arg_value
--- more_headers
Test-Header: i_dont_match
--- response_body
yay, api backend
--- error_code: 200
--- no_error_log
[error]

=== TEST 20: conditions with liquid templating
--- configuration
{
  "services": [
    {
      "id": 42,
      "proxy": {
        "policy_chain": [
          {
            "name": "apicast.policy.routing",
            "configuration": {
              "rules": [
                {
                  "url": "http://test:$TEST_NGINX_SERVER_PORT",
                  "condition": {
                    "operations": [
                      {
                        "match": "header",
                        "header_name": "Service-Id",
                        "op": "==",
                        "value": "{{ service.id }}",
                        "value_type": "liquid"
                      }
                    ]
                  }
                }
              ]
            }
          },
          {
            "name": "apicast.policy.echo"
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
--- more_headers
Service-Id: 42
--- response_body
yay, api backend
--- error_code: 200
--- no_error_log
[error]

=== TEST 20: choosing a Host Header in a routing rule
--- configuration
{
  "services": [
    {
      "id": 42,
      "proxy": {
        "policy_chain": [
          {
            "name": "apicast.policy.routing",
            "configuration": {
              "rules": [
                {
                  "url": "http://test:$TEST_NGINX_SERVER_PORT",
                  "host_header": "example.com",
                  "condition": {
                    "operations": [
                      {
                        "match": "path",
                        "op": "==",
                        "value": "/a_path"
                      }
                    ]
                  }
                }
              ]
            }
          },
          {
            "name": "apicast.policy.echo"
          }
        ]
      }
    }
  ]
}
--- upstream
  # We need to put the 'host_header' of the rule here.
  server_name example.com;

  location /a_path {
     content_by_lua_block {
       -- Check that the Host header was rewritten as indicated in the policy
       -- config.
       local host_header = ngx.req.get_headers()['Host']
       require('luassert').equals('example.com', host_header)

       ngx.say('yay, api backend');
     }
  }
--- request
GET /a_path
--- response_body
yay, api backend
--- error_code: 200
--- no_error_log
[error]

=== TEST 21: matches a rule with an empty condition (it has no operations)
--- configuration
{
  "services": [
    {
      "id": 42,
      "proxy": {
        "policy_chain": [
          {
            "name": "apicast.policy.routing",
            "configuration": {
              "rules": [
                {
                  "url": "http://test:$TEST_NGINX_SERVER_PORT",
                  "condition": {
                    "operations": [
                    ]
                  }
                }
              ]
            }
          },
          {
            "name": "apicast.policy.echo"
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
--- response_body
yay, api backend
--- error_code: 200
--- no_error_log
[error]

=== TEST 22: test with liquid expression
--- configuration
{
  "services": [
    {
      "id": 42,
      "proxy": {
        "policy_chain": [
          {
            "name": "apicast.policy.routing",
            "configuration": {
              "rules": [
                {
                  "url": "http://test:$TEST_NGINX_SERVER_PORT",
                  "condition": {
                    "operations": [
                      {
                        "match": "liquid",
                        "liquid_value": "{{headers.foo}}",
                        "op": "==",
                        "value": "fooValue"
                      }
                    ]
                  }
                }
              ]
            }
          },
          {
            "name": "apicast.policy.echo"
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
--- more_headers
foo: fooValue
--- response_body
yay, api backend
--- error_code: 200
--- no_error_log
[error]

=== TEST 23: test with original request values expression
This is to validate the issue #1088, where a url_rewriting change the path in
the rewrite phase and user does not have a way to route the policy. This is to
validate that a user scenario is working correctly. 
--- configuration
{
  "services": [
    {
      "id": 42,
      "proxy": {
        "policy_chain": [
          {
            "name": "apicast.policy.routing",
            "configuration": {
              "rules": [
                {
                  "url": "http://test:$TEST_NGINX_SERVER_PORT",
                  "condition": {
                    "operations": [
                      {
                        "match": "liquid",
                        "liquid_value": "{{ original_request.path }}",
                        "op": "==",
                        "value": "/bridge-1"
                      }
                    ]
                  }
                }
              ]
            }
          },
          {
            "name": "url_rewriting",
            "configuration": {
              "commands": [
                {
                  "op": "sub",
                  "regex": "^/bridge",
                  "replace": "/"
                }
              ]
            }
          },
          {
            "name": "apicast.policy.echo"
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
GET /bridge-1
--- response_body
yay, api backend
--- error_code: 200
--- no_error_log
[error]
