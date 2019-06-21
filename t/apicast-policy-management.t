use lib 't';
use Test::APIcast::Blackbox 'no_plan';

run_tests();

__DATA__

=== TEST 1: management accepts configuration
--- configuration
{
  "services": [
    {
      "proxy": {
        "policy_chain": [
          { "name": "apicast.policy.management",
            "configuration": { } }
        ]
      }
    }
  ]
}
--- request
GET /status/info
--- error_code: 200
--- no_error_log
[error]
