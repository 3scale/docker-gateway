use lib 't';
use Test::APIcast::Blackbox 'no_plan';

run_tests();

__DATA__

=== TEST 1: More than 1000 services
This test is to validate that APICAST_SERVICE_CACHE_SIZE is working correctly,
because more than 1000 services can hit the limit of the cache and some
services can be lost, related THREESCALE-5308
--- env eval
(
  'APICAST_SERVICE_CACHE_SIZE' => "2000",
)
--- backend
  location /transactions/authrep.xml {
    content_by_lua_block {
      ngx.say('yay, api backend');
    }
  }
--- configuration env eval
my $res = [];
for(my $i = 0; $i < 1600; $i = $i + 1 ) {
  my $s = <<EOF;
{
      "id": $i,
      "backend_version":  1,
      "backend_authentication_type": "service_token",
      "backend_authentication_value": "token-value",
      "proxy": {
        "hosts": [
          "test-$i"
        ],
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/",
        "proxy_rules": [
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 2 }
        ],
        "policy_chain": [
          { "name": "apicast.policy.apicast" }
        ]
      }
    }
EOF
  push @$res, $s;
}
my $str = CORE::join(',', @$res);
<<EOF;
{"services": [$str]}
EOF
--- upstream
  location / {
     content_by_lua_block {
       ngx.say('yay, api backend');
     }
  }
--- request
GET /?user_key=value
--- more_headers
Host: test-0
--- response_body
yay, api backend
--- error_code: 200
--- no_error_log
[error]

