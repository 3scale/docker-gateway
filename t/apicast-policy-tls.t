use lib 't';
use Test::APIcast::Blackbox 'no_plan';

run_tests();

__DATA__

=== TEST 1: tls accepts configuration
--- configuration
{
  "services": [
    {
      "proxy": {
        "policy_chain": [
          { "name": "apicast.policy.tls",
            "configuration": { } },
          { "name": "apicast.policy.echo" }
        ]
      }
    }
  ]
}
--- request
GET /t
--- response_body
GET /t HTTP/1.1
--- error_code: 200
--- no_error_log
[error]
