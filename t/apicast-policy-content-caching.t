use lib 't';
use Test::APIcast::Blackbox 'no_plan';
use File::Path 'rmtree';

require("policies.pl");

# This is to make sure tha cache is cleaned after all and before each request
sub clean_cache {
  rmtree([ "/tmp/cache/" ]);
}
add_block_preprocessor(sub {
    clean_cache();
});

add_cleanup_handler(sub {
    clean_cache();
});

use Cwd qw(getcwd abs_path);
my $cwd = getcwd();
$ENV{LUA_PATH} = "$ENV{LUA_PATH};$cwd/t/helpers/?.lua";

# Can't run twice because it matters for caching
repeat_each(1);
run_tests();

__DATA__

=== TEST 1: Enables content caching
--- configuration
{
  "services": [
    {
      "id": 42,
      "proxy": {
        "hosts": ["one"],
        "policy_chain": [
          {
            "name": "apicast.policy.content_caching",
            "version": "builtin",
            "configuration": {
              "rules": [
                {
                  "cache": true,
                  "header": "X-Cache-Status",
                  "condition": {
                    "combine_op": "and",
                    "operations": [
                      {
                        "left": "oo",
                        "op": "==",
                        "right": "oo"
                      }
                    ]
                  }
                }
              ]
            }
          },
          {
            "name": "apicast.policy.upstream",
            "configuration":
              {
                "rules": [ { "regex": "/", "url": "http://test:$TEST_NGINX_SERVER_PORT/" } ]
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
       ngx.say('yay, api backend');
     }
  }
--- request eval
["GET /foo", "GET /foo", "GET /foo", "GET /metrics"]
--- more_headers eval
["Host: one", "Host: one", "Host: one", "Host: metrics"]
--- expected_response_body_like_multiple eval
[
"yay, api backend\n",
"yay, api backend\n",
"yay, api backend\n",
[
    qr/content_caching\{status="HIT"\} 2/,
    qr/content_caching\{status="MISS"\} 1/,
]]
--- error_code eval
[200, 200, 200, 200]
--- response_headers eval
["X-Cache-Status: MISS", "X-Cache-Status: HIT", "X-Cache-Status: HIT", "X-Cache-Status: "]
--- no_error_log
[error]

=== TEST 2: No operation match do not cache the request
--- configuration
{
  "services": [
    {
      "id": 42,
      "proxy": {
        "policy_chain": [
          {
            "name": "apicast.policy.content_caching",
            "version": "builtin",
            "configuration": {
              "rules": [
                {
                  "cache": true,
                  "header": "X-Cache-Status",
                  "condition": {
                    "combine_op": "and",
                    "operations": [
                      {
                        "left": "oo",
                        "op": "==",
                        "right": "false"
                      }
                    ]
                  }
                }
              ]
            }
          },
          {
            "name": "apicast.policy.upstream",
            "configuration":
              {
                "rules": [ { "regex": "/", "url": "http://test:$TEST_NGINX_SERVER_PORT/" } ]
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
       ngx.say('yay, api backend');
     }
  }
--- request eval
["GET /foo"]
--- response_body eval
["yay, api backend\n"]
--- error_code: 200
--- response_headers
!X-Cache-Status
--- no_error_log
[error]

=== TEST 3: Multiple rules
--- configuration
{
  "services": [
    {
      "id": 42,
      "proxy": {
        "policy_chain": [
          {
            "name": "apicast.policy.content_caching",
            "version": "builtin",
            "configuration": {
              "rules": [
                {
                  "cache": true,
                  "header": "X-Cache-Status",
                  "condition": {
                    "combine_op": "and",
                    "operations": [
                      {
                        "left": "oo",
                        "op": "==",
                        "right": "false"
                      }
                    ]
                  }
                },
                {
                  "cache": true,
                  "header": "X-Cache-Second",
                  "condition": {
                    "combine_op": "and",
                    "operations": [
                      {
                        "left": "oo",
                        "op": "==",
                        "right": "oo"
                      }
                    ]
                  }
                }
              ]
            }
          },
          {
            "name": "apicast.policy.upstream",
            "configuration":
              {
                "rules": [ { "regex": "/", "url": "http://test:$TEST_NGINX_SERVER_PORT/" } ]
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
       ngx.say('yay, api backend');
     }
  }
--- request eval
["GET /foo", "GET /foo"]
--- response_body eval
["yay, api backend\n", "yay, api backend\n"]
--- error_code eval
[200, 200]
--- response_headers eval
["X-Cache-Second: MISS", "X-Cache-Second: HIT"]
--- no_error_log
[error]

=== TEST 5: Not matching path is not hitting the cache
--- configuration
{
  "services": [
    {
      "id": 42,
      "proxy": {
        "policy_chain": [
          {
            "name": "apicast.policy.content_caching",
            "version": "builtin",
            "configuration": {
              "rules": [
                {
                  "cache": true,
                  "header": "X-Cache-Status",
                  "condition": {
                    "combine_op": "and",
                    "operations": [
                      {
                        "left": "{{uri}}",
                        "left_type": "liquid",
                        "op": "==",
                        "right": "/foo"
                      }
                    ]
                  }
                }
              ]
            }
          },
          {
            "name": "apicast.policy.upstream",
            "configuration":
              {
                "rules": [ { "regex": "/", "url": "http://test:$TEST_NGINX_SERVER_PORT/" } ]
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
       ngx.say('yay, api backend');
     }
  }
--- request eval
["GET /foo", "GET /test"]
--- response_body eval
["yay, api backend\n", "yay, api backend\n"]
--- error_code eval
[200, 200]
--- response_headers eval
["X-Cache-Status: MISS", "!X-Cache-Status"]
--- no_error_log
[error]

=== TEST 6: Different cache status codes
--- env eval
(
  'APICAST_CACHE_STATUS_CODES' => "201 302",
)
--- configuration
{
  "services": [
    {
      "id": 42,
      "proxy": {
        "policy_chain": [
          {
            "name": "apicast.policy.content_caching",
            "version": "builtin",
            "configuration": {
              "rules": [
                {
                  "cache": true,
                  "header": "X-Cache-Status",
                  "condition": {
                    "combine_op": "and",
                    "operations": [
                      {
                        "left": "oo",
                        "op": "==",
                        "right": "oo"
                      }
                    ]
                  }
                }
              ]
            }
          },
          {
            "name": "apicast.policy.upstream",
            "configuration":
              {
                "rules": [ { "regex": "/", "url": "http://test:$TEST_NGINX_SERVER_PORT/" } ]
              }
          }
        ]
      }
    }
  ]
}
--- upstream
  location /foo {
     content_by_lua_block {
       ngx.say('ok');
     }
  }

  location /redirect {
     content_by_lua_block {
       ngx.status = 302
       ngx.print('ok');
     }
  }

  location /create {
     content_by_lua_block {
       ngx.status = 201
       ngx.print('ok');
     }
  }
--- request eval
["GET /foo", "GET /foo", "GET /redirect", "GET /redirect", "GET /create", "GET /create"]
--- response_body eval
["ok\n", "ok\n", "ok", "ok", "ok", "ok"]
--- error_code eval
[200, 200, 302, 302, 201, 201]
--- response_headers eval
[
  "X-Cache-Status: MISS",
  "X-Cache-Status: MISS",
  "X-Cache-Status: MISS",
  "X-Cache-Status: HIT",
  "X-Cache-Status: MISS",
  "X-Cache-Status: HIT"
]
--- no_error_log
[error]

=== TEST 7: Cache-control header
--- configuration
{
  "services": [
    {
      "id": 42,
      "proxy": {
        "policy_chain": [
          {
            "name": "apicast.policy.content_caching",
            "version": "builtin",
            "configuration": {
              "rules": [
                {
                  "cache": true,
                  "header": "X-Cache-Status",
                  "condition": {
                    "combine_op": "and",
                    "operations": [
                      {
                        "left": "oo",
                        "op": "==",
                        "right": "oo"
                      }
                    ]
                  }
                }
              ]
            }
          },
          {
            "name": "apicast.policy.upstream",
            "configuration":
              {
                "rules": [ { "regex": "/", "url": "http://test:$TEST_NGINX_SERVER_PORT/" } ]
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
       ngx.header["Cache-Control"] = "no-cache"
       ngx.say('yay, api backend');
     }
  }
--- request eval
["GET /foo", "GET /foo"]
--- response_body eval
["yay, api backend\n", "yay, api backend\n"]
--- error_code eval
[200, 200]
--- response_headers eval
["X-Cache-Status: MISS", "X-Cache-Status: MISS"]
--- no_error_log
[error]
