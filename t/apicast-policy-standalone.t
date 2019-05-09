use lib 't';
use Test::APIcast::Blackbox 'no_plan';

sub Test::Base::Filter::eval_self {
    my ($self, $input) = @_;
    my $block = $self->current_block;

    {
        my @ARGV = ($block);
        my @return = CORE::eval($input);

        return $@ if $@;
        return @return;
    }
}


run_tests();

__DATA__

=== TEST 1: standalone accepts configuration
--- environment_file: standalone
--- configuration_format: yaml
--- configuration
server:
  listen:
  - port: $TEST_NGINX_SERVER_PORT
    name: test
routes:
  - match:
      uri_path: /t
      server_port: test
    destination:
      service: echo
internal:
- name: echo
  policy_chain:
  - policy: apicast.policy.echo
--- request
GET /t
--- response_body
GET /t HTTP/1.1
--- error_code: 200
--- no_error_log
[error]
[warn]



=== TEST 2: standalone can point to external destination
--- environment_file: standalone
--- configuration_format: yaml
--- configuration
server:
  listen:
  - port: $TEST_NGINX_SERVER_PORT
    name: test
routes:
  - match:
      uri_path: /t
      server_port: test
    destination:
      upstream: test-mock
external:
  - name: test-mock
    server: http://mock:$TEST_NGINX_SERVER_PORT
--- upstream_name: mock
--- upstream
location = /t {
  echo "test";
}
--- request
GET /t
--- response_body
test
--- error_code: 200
--- no_error_log
[error]
[warn]



=== TEST 3: data-uri encoded yaml configuration
--- environment_file: standalone
--- env eval_self
use URI;

my ($self) = @_;
my $block = $self->current_block;
my $format = $block->configuration_format;
my $configuration = Test::Nginx::Util::expand_env_in_config($block->configuration);

my $u = URI->new("data:");
$u->media_type("application/$format");
$u->data(scalar($configuration));

$block->set_value('configuration', '');

(
  'APICAST_CONFIGURATION' => $u->as_string,
)
--- configuration_file:
--- configuration_format: yaml
--- configuration env
server:
  listen:
  - port: $TEST_NGINX_SERVER_PORT
    name: test
routes:
  - match:
      uri_path: /t
      server_port: test
    destination:
      service: echo
internal:
  - name: echo
    policy_chain:
    - policy: apicast.policy.echo
--- request
GET /t
--- response_body
GET /t HTTP/1.1
--- error_code: 200
--- no_error_log
[error]
[warn]
