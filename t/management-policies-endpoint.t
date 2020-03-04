use lib 't';
use Test::APIcast::Blackbox 'no_plan';

BEGIN {
    $ENV{TEST_NGINX_MANAGEMENT_SERVER_NAME} = 'management';
}

env_to_apicast(
    'APICAST_CONFIGURATION_LOADER' => 'test'
);

# Converts what's in the 'expected_json' block and the body to JSON and
# compares them. Raises and error when they do not match.
require('policies.pl');

run_tests();

__DATA__

=== TEST 1: GET /policies
Check that the endpoint returns the manifests of all the built-in policies.
--- request
GET /policies
--- more_headers
Host: management
--- response_headers
Content-Type: application/json; charset=utf-8
--- expected_json eval
use JSON;
encode_json $::policies->();
--- error_code: 200
--- no_error_log
[error]

=== TEST 2: expose only policies
APICAST_MANAGEMENT_API=policies enables the endpoint without enabling other
status info
--- env eval
(APICAST_MANAGEMENT_API => "policies")
--- request eval
["GET /policies", "GET /status/info"]
--- error_code eval
[ 200, 404]
--- expected_json eval
use JSON;
encode_json $::policies->();
--- no_error_log
[error]
