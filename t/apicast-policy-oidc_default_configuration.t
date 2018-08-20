use lib 't';
use Test::APIcast::Blackbox 'no_plan';

our $private_key = `cat t/fixtures/rsa.pem`;
my $public_key = `cat t/fixtures/rsa.pub`;
our $public_key_oneline = join('', grep { length($_) eq 64 } split(/\R/, $public_key));


repeat_each(2);

run_tests();

__DATA__

=== TEST 1: OIDC Default configuration policy can override private key
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
        ],
        policy_chain => [
          { name => 'apicast.policy.oidc_default_configuration',
            configuration => { overrides => [ { key => 'public_key', value => $::public_key_oneline } ]} },
          { name => 'apicast.policy.apicast' },
        ],
    }
  }],
  oidc => [{
    issuer => 'https://example.com/auth/realms/apicast',
    config => { openid => { id_token_signing_alg_values_supported => [ 'RS256' ] } }
  }]
});
--- upstream
  location /t {
    echo "yes";
  }
--- backend
  location = /transactions/oauth_authrep.xml {
    content_by_lua_block {
      local expected = "provider_key=fookey&service_id=42&usage%5Bhits%5D=1&app_id=appid"
      require('luassert').same(ngx.decode_args(expected), ngx.req.get_uri_args(0))
    }
  }
--- request
GET /t
--- more_headers eval
use Crypt::JWT qw(encode_jwt);
my $jwt = encode_jwt(payload => {
  aud => 'appid',
  nbf => 0,
  iss => 'https://example.com/auth/realms/apicast',
  exp => time + 3600 }, key => \$::private_key, alg => 'RS256');
["Authorization: Bearer $jwt", "Authorization: Bearer $jwt"]
--- response_body
yes
--- error_code: 200
--- no_error_log
[error]
