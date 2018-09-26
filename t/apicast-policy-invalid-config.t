use lib 't';
use Test::APIcast::Blackbox 'no_plan';

use Cwd qw(abs_path);

BEGIN {
    $ENV{TEST_NGINX_APICAST_POLICY_LOAD_PATH} = 't/fixtures/policies';
}

env_to_apicast(
    'APICAST_POLICY_LOAD_PATH' => abs_path($ENV{TEST_NGINX_APICAST_POLICY_LOAD_PATH}),
);

repeat_each(1);
run_tests();

__DATA__

=== TEST 1: policy with invalid configuration
In this test, we use an example policy that requires a 'message' param in the
configuration. We are going to initialize the policy with an empty
configuration and check that Apicast exits.
--- configuration
{
  "services": [
    {
      "id": 42,
      "proxy": {
        "policy_chain": [
          { "name": "example_policy", "version": "1.0.0", "configuration": { } },
          { "name": "apicast.policy.echo" }
        ]
      }
    }
  ]
}
--- request
GET /test
--- response_body
GET /test HTTP/1.1
--- error_code: 200
--- error_log
Policy example_policy crashed in .new()
