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
    my ($block, $body) = @_;

    use JSON;

    my $expected_json = $block->expected_json;

    if (!$expected_json) {
      return
    }
    my $got = from_json($body);
    my $expected = from_json($expected_json);

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
