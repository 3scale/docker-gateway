use lib 't';
use Test::APIcast::Blackbox 'no_plan';

use Cwd qw(abs_path);

BEGIN {
    $ENV{TEST_NGINX_APICAST_POLICY_LOAD_PATH} = 't/fixtures/policies';
}

env_to_apicast(
    'APICAST_POLICY_LOAD_PATH' => abs_path($ENV{TEST_NGINX_APICAST_POLICY_LOAD_PATH}),
);

repeat_each();
run_tests();

__DATA__

=== TEST 1: policy with invalid configuration return 503
--- configuration
{
  "services": [
    {
      "id": 42,
      "proxy": {
        "policy_chain": [
          { "name": "example_policy", "version": "1.0.0", "configuration": { } },
          { "name": "apicast.policy.on_failed", "configuration": {} },
          { "name": "apicast.policy.echo" }
        ]
      }
    }
  ]
}
--- request
GET /test
--- error_code: 503
--- error_log
Stop request because policy: 'example_policy' failed, error=


=== TEST 2: policy with access phase issues return 503
--- configuration
{
  "services": [
    {
      "id": 42,
      "proxy": {
        "policy_chain": [
          {
            "name": "example_policy",
            "version": "1.0.0",
            "configuration": {
              "message": "foo",
              "fail_access": true
            }
          },
          {
            "name": "apicast.policy.on_failed",
            "configuration": {}
          },
          {
            "name": "apicast.policy.echo"
          }
        ]
      }
    }
  ]
}
--- request
GET /test
--- error_code: 503
--- error_log
Stop request because policy: 'example_policy' failed, error=


=== TEST 3: policy with access phase issues return provided status code
--- configuration
{
  "services": [
    {
      "id": 42,
      "proxy": {
        "policy_chain": [
          {
            "name": "example_policy",
            "version": "1.0.0",
            "configuration": {
              "message": "foo",
              "fail_access": true
            }
          },
          {
            "name": "apicast.policy.on_failed",
            "configuration": {
              "error_status_code": 401
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
--- request
GET /test
--- error_code: 401
--- error_log
Stop request because policy: 'example_policy' failed, error='
