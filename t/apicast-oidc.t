use lib 't';
use Test::APIcast::Blackbox 'no_plan';

our $private_key = `cat t/fixtures/rsa.pem`;
our $public_key = `cat t/fixtures/rsa.pub`;


repeat_each(1);
run_tests();

__DATA__

=== TEST 1: Verify JWT
--- configuration env eval
use JSON qw(to_json);

to_json({
  services => [{
    id => 42,
    backend_version => 'oauth',
    backend_authentication_type => 'provider_key',
    backend_authentication_value => 'fookey',
    proxy => {
        authentication_method => 'oidc',
        oidc_issuer_endpoint => 'https://example.com/auth/realms/apicast',
        api_backend => "http://test:$TEST_NGINX_SERVER_PORT/",
        proxy_rules => [
          { pattern => '/', http_method => 'GET', metric_system_name => 'hits', delta => 1  }
        ]
    }
  }],
  oidc => [{
    issuer => 'https://example.com/auth/realms/apicast',
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
  iss => 'https://example.com/auth/realms/apicast',
  exp => time + 3600 }, key => \$::private_key, alg => 'RS256', extra_headers => { kid => 'somekid' });
"Authorization: Bearer $jwt"
--- no_error_log
[error]



=== TEST 2: Report calls to 3scale backend (same as TEST 1, but with two requests to trigger async reporting)
This is the same test as TEST 1, but done twice to trigger asynchronous reporting from post_action to
test https://issues.jboss.org/browse/THREESCALE-1080.
--- configuration env eval
use JSON qw(to_json);

to_json({
  services => [{
    id => 42,
    backend_version => 'oauth',
    backend_authentication_type => 'provider_key',
    backend_authentication_value => 'fookey',
    proxy => {
        authentication_method => 'oidc',
        oidc_issuer_endpoint => 'https://example.com/auth/realms/apicast',
        api_backend => "http://test:$TEST_NGINX_SERVER_PORT/",
        proxy_rules => [
          { pattern => '/', http_method => 'GET', metric_system_name => 'hits', delta => 1  }
        ]
    }
  }],
  oidc => [{
    issuer => 'https://example.com/auth/realms/apicast',
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
--- request eval
[ "GET /test", "GET /test" ]
--- error_code eval
[ 200, 200 ]
--- more_headers eval
use Crypt::JWT qw(encode_jwt);
my $jwt = encode_jwt(payload => {
  aud => 'something',
  azp => 'appid',
  sub => 'someone',
  iss => 'https://example.com/auth/realms/apicast',
  exp => time + 3600 }, key => \$::private_key, alg => 'RS256', extra_headers => { kid => 'somekid' });
["Authorization: Bearer $jwt", "Authorization: Bearer $jwt"]
--- no_error_log
[error]



=== TEST 3: Invalid OIDC configuration
Prints error message in the log.
--- configuration env eval
use JSON qw(to_json);

to_json({
  services => [{
    id => 42,
    backend_version => 'oauth',
    backend_authentication_type => 'provider_key',
    backend_authentication_value => 'fookey',
    proxy => {
        authentication_method => 'oidc',
        oidc_issuer_endpoint => 'https://example.com/auth/realms/apicast',
        api_backend => "http://test:$TEST_NGINX_SERVER_PORT/",
        proxy_rules => [
          { pattern => '/', http_method => 'GET', metric_system_name => 'hits', delta => 1  }
        ]
    }
  }],
  oidc => [{
    keys => { somekid => { pem => $::public_key } },
  }]
});
--- request: GET /test
--- error_code: 403
--- more_headers eval
use Crypt::JWT qw(encode_jwt);
my $jwt = encode_jwt(payload => {
  aud => 'something',
  azp => 'appid',
  sub => 'someone',
  iss => 'https://example.com/auth/realms/apicast',
  exp => time + 3600 }, key => \$::private_key, alg => 'RS256', extra_headers => { kid => 'somekid' });
"Authorization: Bearer $jwt"
--- error_log
failed to initialize OpenID Connect for service 42: missing OIDC configuration
--- log_level: warn


=== TEST 4: Sets the "no-body" option when contacting the 3scale backend
--- configuration env eval
use JSON qw(to_json);

to_json({
  services => [{
    id => 42,
    backend_version => 'oauth',
    backend_authentication_type => 'provider_key',
    backend_authentication_value => 'fookey',
    proxy => {
        authentication_method => 'oidc',
        oidc_issuer_endpoint => 'https://example.com/auth/realms/apicast',
        api_backend => "http://test:$TEST_NGINX_SERVER_PORT/",
        proxy_rules => [
          { pattern => '/', http_method => 'GET', metric_system_name => 'hits', delta => 1  }
        ]
    }
  }],
  oidc => [{
    issuer => 'https://example.com/auth/realms/apicast',
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
      local luassert = require('luassert')
      luassert.same(ngx.var['http_3scale_options'], 'rejection_reason_header=1&limit_headers=1&no_body=1')

      local expected = "provider_key=fookey&service_id=42&usage%5Bhits%5D=1&app_id=appid"
      luassert.same(ngx.decode_args(expected), ngx.req.get_uri_args(0))
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
  iss => 'https://example.com/auth/realms/apicast',
  exp => time + 3600 }, key => \$::private_key, alg => 'RS256', extra_headers => { kid => 'somekid' });
"Authorization: Bearer $jwt"
--- no_error_log
[error]

=== TEST 5: Use different claim for app_id
--- configuration env eval
use JSON qw(to_json);

to_json({
  services => [{
    id => 42,
    backend_version => 'oauth',
    backend_authentication_type => 'provider_key',
    backend_authentication_value => 'fookey',
    proxy => {
        authentication_method => 'oidc',
        oidc_issuer_endpoint => 'https://example.com/auth/realms/apicast',
        oidc_client_id => '{{ foo }}',
        api_backend => "http://test:$TEST_NGINX_SERVER_PORT/",
        proxy_rules => [
          { pattern => '/', http_method => 'GET', metric_system_name => 'hits', delta => 1  }
        ]
    }
  }],
  oidc => [{
    issuer => 'https://example.com/auth/realms/apicast',
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
      local expected = "provider_key=fookey&service_id=42&usage%5Bhits%5D=1&app_id=fooid"
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
  foo => 'fooid',
  iss => 'https://example.com/auth/realms/apicast',
  exp => time + 3600 }, key => \$::private_key, alg => 'RS256', extra_headers => { kid => 'somekid' });
"Authorization: Bearer $jwt"
--- no_error_log
[error]
