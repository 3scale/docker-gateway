use Test::APIcast::Blackbox 'no_plan';

our $private_key = `cat t/fixtures/rsa.pem`;
our $public_key = `cat t/fixtures/rsa.pub`;

run_tests();

__DATA__

=== TEST 1: multi service configuration limited to specific service
--- env eval
("APICAST_SERVICES_LIST", "42,21")
--- configuration
{
  "services": [
    {
      "backend_version": 1,
      "proxy": {
        "hosts": [
          "one"
        ],
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/",
        "proxy_rules": [
          {
            "http_method": "GET",
            "delta": 1,
            "metric_system_name": "one",
            "pattern": "/"
          }
        ]
      },
      "id": 42
    },
    {
      "proxy": {
        "hosts": [
          "two"
        ]
      },
      "id": 11
    }
  ]
}
--- backend
  location /transactions/authrep.xml {
    content_by_lua_block { ngx.exit(200) }
  }
--- upstream
  location ~ / {
     echo 'yay, api backend';
  }
--- pipelined_requests eval
["GET /?user_key=1","GET /?user_key=2"]
--- more_headers eval
["Host: one", "Host: two"]
--- response_body eval
["yay, api backend\n", ""]
--- error_code eval
[200, 404]



=== TEST 2: multi service configuration limited with Regexp Filter
--- env eval
("APICAST_SERVICES_FILTER_BY_URL", "^on*")
--- configuration
{
  "services": [
    {
      "backend_version": 1,
      "proxy": {
        "hosts": [
          "one"
        ],
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/",
        "proxy_rules": [
          {
            "http_method": "GET",
            "delta": 1,
            "metric_system_name": "one",
            "pattern": "/"
          }
        ]
      },
      "id": 42
    },
    {
      "proxy": {
        "hosts": [
          "two"
        ]
      },
      "id": 11
    }
  ]
}
--- backend
  location /transactions/authrep.xml {
    content_by_lua_block { ngx.exit(200) }
  }
--- upstream
  location ~ / {
     echo 'yay, api backend';
  }
--- pipelined_requests eval
["GET /?user_key=1","GET /?user_key=2"]
--- more_headers eval
["Host: one", "Host: two"]
--- response_body eval
["yay, api backend\n", ""]
--- error_code eval
[200, 404]

=== TEST 3: multi service configuration limited with Regexp Filter and service list
--- env eval
(
"APICAST_SERVICES_FILTER_BY_URL", "^on*",
"APICAST_SERVICES_LIST", "21"
)
--- configuration
{
  "services": [
    {
      "backend_version": 1,
      "proxy": {
        "hosts": [
          "one"
        ],
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/",
        "proxy_rules": [
          {
            "http_method": "GET",
            "delta": 1,
            "metric_system_name": "one",
            "pattern": "/"
          }
        ]
      },
      "id": 42
    },
    {
      "backend_version": 1,
      "proxy": {
        "hosts": [
          "two"
        ],
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/two",
        "proxy_rules": [
          {
            "http_method": "GET",
            "delta": 1,
            "metric_system_name": "one",
            "pattern": "/"
          }
        ]
      },
      "id": 21
    },
    {
      "proxy": {
        "hosts": [
          "three"
        ]
      },
      "id": 11
    }
  ]
}
--- backend
  location /transactions/authrep.xml {
    content_by_lua_block { ngx.exit(200) }
  }
--- upstream
  location / {
     echo 'yay, api backend';
  }

  location /two {
     echo 'yay, api backend two';
  }

--- pipelined_requests eval
["GET /?user_key=1","GET /?user_key=2", "GET /?user_key=3"]
--- more_headers eval
["Host: one", "Host: two", "Host: three"]
--- response_body eval
["yay, api backend\n", "yay, api backend two\n", ""]
--- error_code eval
[200, 200, 404]


=== TEST 4: Verify that OIDC is working when filter services.
Related to issues THREESCALE-6042
--- env eval
(
  "APICAST_SERVICES_LIST", "42"
)
--- configuration env eval
use JSON qw(to_json);

to_json({
  services => [
  {
    id => 24,
    backend_version => 'oauth',
    backend_authentication_type => 'provider_key',
    backend_authentication_value => 'fookey',
    proxy => {
        authentication_method => 'oidc',
        oidc_issuer_endpoint => 'https://example.com/auth/realms/apicast_zero',
        api_backend => "http://test:$TEST_NGINX_SERVER_PORT/",
        hosts => ["zero"],
        proxy_rules => [
          { pattern => '/', http_method => 'GET', metric_system_name => 'hits', delta => 1  }
        ]
    }
  },
  {
    id => 42,
    backend_version => 'oauth',
    backend_authentication_type => 'provider_key',
    backend_authentication_value => 'fookey',
    proxy => {
        authentication_method => 'oidc',
        oidc_issuer_endpoint => 'https://example.com/auth/realms/apicast_one',
        api_backend => "http://test:$TEST_NGINX_SERVER_PORT/",
        hosts => ["one"],
        proxy_rules => [
          { pattern => '/', http_method => 'GET', metric_system_name => 'hits', delta => 1  }
        ]
    }
  }
  ],
  oidc => [{
    service_id => 24, 
    issuer => 'https://example.com/auth/realms/apicast_zero',
    config => { id_token_signing_alg_values_supported => [ 'RS256' ] },
    keys => { somekid => { pem => $::public_key } },
  },
  {
    service_id => 42,
    issuer => 'https://example.com/auth/realms/apicast_one',
    config => { id_token_signing_alg_values_supported => [ 'RS256' ] },
    keys => { somekid => { pem => $::public_key } },
  }]
});
--- upstream
  location /test {
    echo "yes";
  }
--- backend
  location = /transactions/oauth_authrep.xml {
    content_by_lua_block {
      local expected = "provider_key=fookey&service_id=42&usage%5Bhits%5D=1&app_id=appid"
      require('luassert').same(ngx.decode_args(expected), ngx.req.get_uri_args(0))
    }
  }
--- request: GET /test
--- error_code: 200
--- more_headers eval
use Crypt::JWT qw(encode_jwt);
my $jwt = encode_jwt(payload => {
  aud => 'something',
  azp => 'appid',
  sub => 'someone',
  iss => 'https://example.com/auth/realms/apicast_one',
  exp => time + 3600 }, key => \$::private_key, alg => 'RS256', extra_headers => { kid => 'somekid' });
"Authorization: Bearer $jwt\r\nHost: one";
--- no_error_log
[error]
