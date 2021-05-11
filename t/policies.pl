use File::Spec::Functions qw(catfile);
use Cwd qw(abs_path);
use File::Basename; qw(basename);
use File::Find ();
use File::Slurp qw(read_file);
use JSON qw(from_json);
use Test::Deep;


our $policies = sub ($) {
    my $path = shift;

    my %policies = ();

    my $add_policy = sub {
        my $policy_name = shift;
        my $policy_manifest_path = shift;

        my @versions = $policies{$policy_name} || ();
        my $manifest = read_file($policy_manifest_path);
        my $json = decode_json($manifest);
        push @versions, $json;

        $policies{$policy_name} = \@versions;
    };

    my $builtin_policies = sub {


        if (/^apicast-policy\.json\z/s) {
            my $policy_name = basename($File::Find::dir);

            $add_policy->($policy_name, $File::Find::name);
        }
    };

    my $custom_policies = sub {
        if (/^apicast-policy\.json\z/s) {
            my $policy_dir = dirname($File::Find::dir);
            my $policy_name = basename($policy_dir);

            $add_policy->($policy_name, $File::Find::name);
        }
    };

    File::Find::find({wanted => \&$builtin_policies, no_chdir=>0 }, catfile($ENV{APICAST_DIR}, "src/apicast/policy"));

    if ($path) {
        File::Find::find({wanted => \&$custom_policies, no_chdir=>0 }, abs_path($path));
    }

    my %json = ('policies' => \%policies);

    return \%json;
};

our $expect_json = sub ($) {
    use Data::Dumper;
    my ($block, $body, $req_idx, $repeated_req_idx, $dry_run) = @_;

    if (!$block->expected_json) {
        return "";
    }

    my @asserts = @{$block->{expected_json}};
    my @val = shift @asserts;
    my $expected_json = "";
    if (ref(${val}[0]) eq 'ARRAY') {
      $expected_json = ${val}[0]->[$req_idx];
    }else{
      $expected_json = ${val}[0];
    }


    # Because from_json can croak on invalid json, this will enable undef value
    # on invalid body
    my $got = eval { from_json($body) };
    my $expected = eval {from_json($expected_json)};
    cmp_deeply(
        $got,
        $expected,
        "the body matches the expected JSON structure"
    );
};

add_response_body_check($expect_json);



# This response body helper function check is like a response_body_like but it
# can be used with multiple values for a single request.
#
# An usage example can be like this:
# --- expected_response_body_like_multiple eval
# [
# qr/.*/,
# qr/[0-9]*/,
# [
#     qr/^a.*/,
#     qr/Z$/
# ]]
#
# Where the third request will validate that starts with a and finish with Z.
add_response_body_check(sub {
    my ($block, $body, $req_idx, $repeated_req_idx, $dry_run) = @_;

    if (!$block->expected_response_body_like_multiple) {
        return "";
    }
    my @asserts = @{$block->{expected_response_body_like_multiple}};
    my $assertValues = ${asserts}[0][$req_idx];
    if (ref(${assertValues}) eq 'ARRAY') {
        foreach my $regexp(@{$assertValues}){
            if (!($body =~ m/$regexp/)) {
                fail(sprintf("Regular expression: '%s' does not match with the body: \n %s",$regexp, $body));
            }
        }
    }else{
        if (!($body =~ m/$assertValues/)) {
            fail(sprintf("Regular expression: '%s' does not match with the body: \n %s",$assertValues, $body));
        }
    }
});



our $json_keys = sub ($) {
    my ($block, $body, $req_idx, $repeated_req_idx, $dry_run) = @_;

    use JSON;
    use Data::Dumper;

    my $expected_keys = $block->json_keys;

    if (!$expected_keys) {
      return
    }

    my $parsed_body = eval {from_json($body)};
    if (!$parsed_body) {
      fail(sprintf("INVALID response body json: %s", $body))
    }

    my $expected_keys_matches  = eval {from_json($expected_keys)};
    if (!$expected_keys_matches) {
      fail(sprintf("INVALID json: %s", $expected_keys))
    }

    if (! ref($expected_keys_matches) eq 'ARRAY') {
      fail(sprintf("INVALID json, need to be an array: %s", $expected_keys))
    }

    foreach my $matcher(@{$expected_keys_matches}) {
      my $key_to_check = $matcher->{'key'};
      my $expected_val = $matcher->{'val'};
      my $expected_operation = $matcher->{'op'} || '==';
      my $val = $parsed_body->{$key_to_check};
      # print(Dumper($matcher, $val, $expected_val));
      if ( $expected_operation eq '==' ) {
          cmp_deeply(
              $val,
              $expected_val,
              sprintf("JsonResponse: Value for key '%s' matches correctly", $key_to_check)
          );
      } elsif ($expected_operation eq 'regexp' ) {
          if (!($val =~ m/$expected_val/)) {
              fail(sprintf("Regular expression: '%s' does not match with the value: \n %s", $expected_val, $val));
          }
      } else {
          fail(sprintf("No valid matching operation: '%s'", $expected_operation));
      }
    }
};

add_response_body_check($json_keys);
