use lib 't';
use Test::APIcast::Blackbox 'no_plan';

run_tests();

__DATA__

=== TEST 1: Set timeouts
In this test we set some timeouts to 1s. To force a read timeout, the upstream
returns part of the response, then waits 3s (more than the timeout defined),
and after that, it returns the rest of the response.
This test uses the "ignore_response" section, because we know that the response
is not going to be complete and that makes the Test::Nginx framework raise an
error. With "ignore_response" that error is ignored.
--- configuration
{
  "services": [
    {
      "id": 42,
      "proxy": {
        "api_backend": "http://example.com:80/",
        "policy_chain": [
          {
            "name": "apicast.policy.upstream_connection",
            "configuration": {
              "connect_timeout": 1,
              "send_timeout": 1,
              "read_timeout": 1
            }
          },
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
       ngx.say("first part")
       ngx.flush(true)
       ngx.sleep(3)
       ngx.say("yay, second part")
     }
  }
--- request
GET /
--- ignore_response
--- error_log
upstream timed out
--- error_code:
