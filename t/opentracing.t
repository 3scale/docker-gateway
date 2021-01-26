use lib 't';
use Test::APIcast::Blackbox 'no_plan';

$ENV{OPENTRACING_TRACER} ||= 'jaeger';

repeat_each(1);
run_tests();


__DATA__
=== TEST 1: OpenTracing
Request passing through APIcast should publish OpenTracing info.
--- configuration
    {
        "services": [
        {
            "proxy": {
            "policy_chain": [
            { "name": "apicast.policy.upstream",
                "configuration":
                {
                    "rules": [ { "regex": "/", "url": "http://echo" } ]
                }
            }
            ]
        }
        }
        ]
    }
--- request
GET /a_path?
--- response_body eval
qr/uber-trace-id: /
--- error_code: 200
--- no_error_log
[error]
--- udp_listen: 6831
--- udp_reply
--- udp_query eval
qr/jaeger.version/
--- wait: 10

=== TEST 2: OpenTracing forward header
Opentracing forward header is send to the upstream.
--- env eval
(
    'OPENTRACING_FORWARD_HEADER' => "foobar"
)
--- configuration
{
  "services": [
    {
      "id": 42,
      "system_name": "foo",
      "proxy": {
        "policy_chain": [
          {
            "name": "apicast.policy.upstream",
            "configuration": {
              "rules": [
                {
                  "regex": "/",
                  "url": "http://test:$TEST_NGINX_SERVER_PORT"
                }
              ]
            }
          }
        ]
      }
    }
  ]
}
--- upstream
  location / {
    content_by_lua_block {
      local headers  = ngx.req.get_headers()
      assert(headers["foobar"] == "value")
    }
  }
--- request
GET /a_path?
--- more_headers eval
"foobar: value"
--- error_code: 200
--- no_error_log
[error]
--- udp_listen: 6831
--- udp_reply
--- udp_query eval
qr/jaeger.version/
--- wait: 10

=== TEST 3: original_request_uri tag
Opentracing custom tag fix for THREESCALE-5669
-- env eval
(
    'OPENTRACING_FORWARD_HEADER' => "foobar"
)
--- configuration
{
  "services": [
    {
      "id": 42,
      "system_name": "foo",
      "proxy": {
        "policy_chain": [
          {
            "name": "apicast.policy.upstream",
            "configuration": {
              "rules": [
                {
                  "regex": "/",
                  "url": "http://test:$TEST_NGINX_SERVER_PORT"
                }
              ]
            }
          }
        ]
      }
    }
  ]
}
--- upstream
  location / {
    content_by_lua_block {
      local headers  = ngx.req.get_headers()
      assert(headers["foobar"] == "value")
    }
  }
--- request
GET /a_path?
--- more_headers eval
"foobar: value"
--- error_code: 200
--- no_error_log
[error]
--- udp_listen: 6831
--- udp_reply
--- udp_query eval
qr/original_request_uri/
--- wait: 10
