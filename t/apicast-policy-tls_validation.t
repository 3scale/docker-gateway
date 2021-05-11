use lib 't';
use Test::APIcast::Blackbox 'no_plan';

env_to_apicast(
    'APICAST_HTTPS_PORT' => "$Test::Nginx::Util::ServerPortForClient",
    'APICAST_HTTPS_CERTIFICATE' => "$Test::Nginx::Util::ServRoot/html/server.crt",
    'APICAST_HTTPS_CERTIFICATE_KEY' => "$Test::Nginx::Util::ServRoot/html/server.key",
    'APICAST_HTTPS_SESSION_REUSE' => 'on',
);

run_tests();

__DATA__

=== TEST 1: TLS Client Certificate is whitelisted and valid
--- configuration eval
use JSON qw(to_json);
use File::Slurp qw(read_file);

to_json({
  services => [{
    proxy => {
        hosts => ['test'],
        policy_chain => [
          { name => 'apicast.policy.tls_validation',
            configuration => {
              whitelist => [
                { pem_certificate => CORE::join('', read_file('t/fixtures/CA/client.crt')) }
              ]
            }
          },
          { name => 'apicast.policy.echo' },
        ]
    }
  }]
});
--- test env
proxy_ssl_verify on;
proxy_ssl_trusted_certificate $TEST_NGINX_SERVER_ROOT/html/ca.crt;
proxy_ssl_certificate $TEST_NGINX_SERVER_ROOT/html/client.crt;
proxy_ssl_certificate_key $TEST_NGINX_SERVER_ROOT/html/client.key;
proxy_pass https://$server_addr:$apicast_port/t;
proxy_set_header Host localhost;
log_by_lua_block { collectgarbage() }
--- response_body
GET /t HTTP/1.0
--- error_code: 200
--- no_error_log
[error]
--- user_files fixture=CA/files.pl eval



=== TEST 2: TLS Client Certificate CA is whitelisted
--- configuration eval
use JSON qw(to_json);
use File::Slurp qw(read_file);

to_json({
  services => [{
    proxy => {
        hosts => ['test'],
        policy_chain => [
          { name => 'apicast.policy.tls_validation',
            configuration => {
              whitelist => [
                { pem_certificate => CORE::join('', read_file('t/fixtures/CA/intermediate-ca.crt')) }
              ]
            }
          },
          { name => 'apicast.policy.echo' },
        ]
    }
  }]
});
--- test env
proxy_ssl_verify on;
proxy_ssl_trusted_certificate $TEST_NGINX_SERVER_ROOT/html/ca.crt;
proxy_ssl_certificate $TEST_NGINX_SERVER_ROOT/html/client.crt;
proxy_ssl_certificate_key $TEST_NGINX_SERVER_ROOT/html/client.key;
proxy_pass https://$server_addr:$apicast_port/t;
proxy_set_header Host localhost;
log_by_lua_block { collectgarbage() }
--- response_body
GET /t HTTP/1.0
--- error_code: 200
--- no_error_log
[error]
--- user_files fixture=CA/files.pl eval



=== TEST 3: TLS Client Certificate is not whitelisted
--- configuration eval
use JSON qw(to_json);
use File::Slurp qw(read_file);

to_json({
  services => [{
    proxy => {
        hosts => ['test'],
        policy_chain => [
          { name => 'apicast.policy.tls_validation',
            configuration => {
              whitelist => [ ]
            }
          },
          { name => 'apicast.policy.echo' },
        ]
    }
  }]
});
--- test env
proxy_ssl_verify on;
proxy_ssl_trusted_certificate $TEST_NGINX_SERVER_ROOT/html/ca.crt;
proxy_ssl_certificate $TEST_NGINX_SERVER_ROOT/html/client.crt;
proxy_ssl_certificate_key $TEST_NGINX_SERVER_ROOT/html/client.key;
proxy_pass https://$server_addr:$apicast_port/t;
proxy_set_header Host localhost;
log_by_lua_block { collectgarbage() }
--- response_body
unable to get local issuer certificate
--- error_code: 400
--- no_error_log
[error]
--- user_files fixture=CA/files.pl eval



=== TEST 4: TLS Client Certificate is not provided
--- configuration eval
use JSON qw(to_json);
use File::Slurp qw(read_file);

to_json({
  services => [{
    proxy => {
        hosts => ['test'],
        policy_chain => [
          { name => 'apicast.policy.tls_validation',
            configuration => {
              whitelist => [ ]
            }
          },
          { name => 'apicast.policy.echo' },
        ]
    }
  }]
});
--- test env
proxy_ssl_verify on;
proxy_ssl_trusted_certificate $TEST_NGINX_SERVER_ROOT/html/ca.crt;
proxy_pass https://$server_addr:$apicast_port/t;
proxy_set_header Host localhost;
log_by_lua_block { collectgarbage() }
--- response_body
Invalid certificate verification context
--- error_code: 400
--- no_error_log
[error]
[alert]
--- user_files fixture=CA/files.pl eval



=== TEST 5: TLS Client Certificate contains whole certificate chain
--- env eval
("APICAST_HTTPS_VERIFY_DEPTH" => 2)
--- configuration eval
use JSON qw(to_json);
use File::Slurp qw(read_file);

to_json({
  services => [{
    proxy => {
        hosts => ['test'],
        policy_chain => [
          { name => 'apicast.policy.tls_validation',
            configuration => {
              whitelist => [
                { pem_certificate => CORE::join('', read_file('t/fixtures/CA/intermediate-ca.crt')) }
              ]
            }
          },
          { name => 'apicast.policy.echo' },
        ]
    }
  }]
});
--- test env
proxy_ssl_verify on;
proxy_ssl_trusted_certificate $TEST_NGINX_SERVER_ROOT/html/ca.crt;
proxy_ssl_certificate $TEST_NGINX_SERVER_ROOT/html/client-bundle.crt;
proxy_ssl_certificate_key $TEST_NGINX_SERVER_ROOT/html/client.key;
proxy_pass https://$server_addr:$apicast_port/t;
proxy_set_header Host localhost;
log_by_lua_block { collectgarbage() }
--- response_body
GET /t HTTP/1.0
--- error_code: 200
--- no_error_log
[error]
--- user_files fixture=CA/files.pl eval
