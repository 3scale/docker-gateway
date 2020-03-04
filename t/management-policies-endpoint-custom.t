use lib 't';
use Test::APIcast::Blackbox 'no_plan';

use Cwd qw(abs_path);

BEGIN {
    $ENV{TEST_NGINX_MANAGEMENT_SERVER_NAME} = 'management';
    $ENV{TEST_NGINX_APICAST_POLICY_LOAD_PATH} = 't/fixtures/policies_endpoint_test/policies';
}

env_to_apicast(
    'APICAST_CONFIGURATION_LOADER' => 'test',
    'APICAST_POLICY_LOAD_PATH' => abs_path($ENV{TEST_NGINX_APICAST_POLICY_LOAD_PATH}),
);

# Converts what's in the 'expected_json' block and the body to JSON and
# compares them. Raises and error when they do not match.
require("policies.pl");

run_tests();

__DATA__

=== TEST 1: GET /policies
Check that the endpoint returns the manifests of all the built-in policies plus
the one in paths specified via config.
We have a directory with policies in 't/fixtures'. There are 2 policies there,
a valid one (example1), and one where the version specified in the manifest and
the one in the policy directory do not match (example2). We need to check that
the later is not returned.
--- request
GET /policies
--- more_headers
Host: management
--- response_headers
Content-Type: application/json; charset=utf-8
--- expected_json eval
use JSON;
my $res = $::policies->($ENV{TEST_NGINX_APICAST_POLICY_LOAD_PATH});
# remove example 2 because its version does not match the manifest
delete $res->{policies}->{example2};
encode_json $res;
--- error_code: 200
--- no_error_log
[error]
