use lib 't';
use Test::APIcast::Blackbox 'no_plan';

require("policies.pl");
# The output varies between requests, so run only once
repeat_each(1);

run_tests();

__DATA__

=== TEST 1: metrics endpoint works
--- configuration
{
}
--- request
GET /metrics
--- more_headers
Host: metrics
--- response_body
# HELP nginx_http_connections Number of HTTP connections
# TYPE nginx_http_connections gauge
nginx_http_connections{state="accepted"} 1
nginx_http_connections{state="active"} 1
nginx_http_connections{state="handled"} 1
nginx_http_connections{state="reading"} 0
nginx_http_connections{state="total"} 1
nginx_http_connections{state="waiting"} 0
nginx_http_connections{state="writing"} 1
# HELP nginx_metric_errors_total Number of nginx-lua-prometheus errors
# TYPE nginx_metric_errors_total counter
nginx_metric_errors_total 0
# HELP openresty_shdict_capacity OpenResty shared dictionary capacity
# TYPE openresty_shdict_capacity gauge
openresty_shdict_capacity{dict="api_keys"} 10485760
openresty_shdict_capacity{dict="batched_reports"} 1048576
openresty_shdict_capacity{dict="batched_reports_locks"} 1048576
openresty_shdict_capacity{dict="cached_auths"} 1048576
openresty_shdict_capacity{dict="configuration"} 10485760
openresty_shdict_capacity{dict="init"} 16384
openresty_shdict_capacity{dict="limiter"} 1048576
openresty_shdict_capacity{dict="locks"} 1048576
openresty_shdict_capacity{dict="prometheus_metrics"} 16777216
# HELP openresty_shdict_free_space OpenResty shared dictionary free space
# TYPE openresty_shdict_free_space gauge
openresty_shdict_free_space{dict="api_keys"} 10412032
openresty_shdict_free_space{dict="batched_reports"} 1032192
openresty_shdict_free_space{dict="batched_reports_locks"} 1032192
openresty_shdict_free_space{dict="cached_auths"} 1032192
openresty_shdict_free_space{dict="configuration"} 10412032
openresty_shdict_free_space{dict="init"} 4096
openresty_shdict_free_space{dict="limiter"} 1032192
openresty_shdict_free_space{dict="locks"} 1032192
openresty_shdict_free_space{dict="prometheus_metrics"} 16662528
--- error_code: 200
--- no_error_log
[error]

=== TEST 2: metric endpoints shows backend responses when the APIcast policy is in the chain
We do a couple of authorized requests to backend (2xx) and a couple of
unauthorized ones (4xx) and check that those metrics are shown correctly when
calling the prometheus metrics endpoint.
To simplify the output of the metrics endpoint, we use an environment config
that does not include the nginx metrics (tested in the previous test).
--- environment_file: t/fixtures/configs/without_nginx_metrics.lua
--- configuration
{
  "services": [
    {
      "id": 42,
      "backend_version":  1,
      "backend_authentication_type": "service_token",
      "backend_authentication_value": "token-value",
      "proxy": {
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/",
        "proxy_rules": [
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 1 }
        ],
        "policy_chain": [
          { "name": "apicast.policy.apicast" }
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
--- backend
  location /transactions/authrep.xml {
    content_by_lua_block {
      -- Check only the user key and assume the rest of params are OK
      if ngx.req.get_uri_args(0)['user_key'] == 'invalid' then
        ngx.exit(403)
      else
        ngx.exit(200)
      end
    }
  }
--- request eval
["GET /?user_key=valid", "GET /?user_key=valid", "GET /?user_key=invalid", "GET /?user_key=invalid", "GET /metrics"]
--- more_headers eval
["", "", "", "", "Host: metrics"]
--- error_code eval
[ 200, 200, 403, 403, 200 ]
--- response_body eval
[ "yay, api backend\x{0a}", "yay, api backend\x{0a}", "Authentication failed", "Authentication failed",
<<'METRICS_OUTPUT'
# HELP nginx_metric_errors_total Number of nginx-lua-prometheus errors
# TYPE nginx_metric_errors_total counter
nginx_metric_errors_total 0
# HELP threescale_backend_calls Calls to the 3scale backend
# TYPE threescale_backend_calls counter
threescale_backend_calls{endpoint="authrep",status="2xx"} 2
threescale_backend_calls{endpoint="authrep",status="4xx"} 2
METRICS_OUTPUT
]
--- no_error_log
[error]

=== TEST 3: metrics endpoint shows auth cache hits and misses when using the 3scale batching policy
We make 3 requests with the same user key. In the output we'll see a miss
from the first request and 2 hits from the others.
We use and env file without the nginx metrics to simplify the output of the
/metrics endpoint.
--- environment_file: t/fixtures/configs/without_nginx_metrics.lua
--- configuration
{
  "services": [
    {
      "id": 42,
      "backend_version":  1,
      "backend_authentication_type": "service_token",
      "backend_authentication_value": "token-value",
      "proxy": {
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/",
        "proxy_rules": [
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 1 }
        ],
        "policy_chain": [
          { "name": "apicast.policy.apicast" },
          { "name": "apicast.policy.3scale_batcher", "configuration": {} }
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
--- backend
  location /transactions/authorize.xml {
    content_by_lua_block {
      ngx.exit(200)
    }
  }

  location /transactions.xml {
    content_by_lua_block {
      ngx.exit(200)
    }
  }
--- request eval
["GET /?user_key=valid", "GET /?user_key=valid", "GET /?user_key=valid", "GET /metrics"]
--- more_headers eval
["", "", "", "Host: metrics"]
--- error_code eval
[ 200, 200, 200, 200 ]
--- response_body eval
[ "yay, api backend\x{0a}", "yay, api backend\x{0a}", "yay, api backend\x{0a}",
<<'METRICS_OUTPUT'
# HELP batching_policy_auths_cache_hits Hits in the auths cache of the 3scale batching policy
# TYPE batching_policy_auths_cache_hits counter
batching_policy_auths_cache_hits 2
# HELP batching_policy_auths_cache_misses Misses in the auths cache of the 3scale batching policy
# TYPE batching_policy_auths_cache_misses counter
batching_policy_auths_cache_misses 1
# HELP nginx_metric_errors_total Number of nginx-lua-prometheus errors
# TYPE nginx_metric_errors_total counter
nginx_metric_errors_total 0
# HELP threescale_backend_calls Calls to the 3scale backend
# TYPE threescale_backend_calls counter
threescale_backend_calls{endpoint="auth",status="2xx"} 1
METRICS_OUTPUT
]
--- no_error_log
[error]

=== TEST 4: the metrics endpoint shows metrics about the upstream
In particular, it shows the status codes and the response times
--- configuration
{
  "services": [
    {
      "id": 42,
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
       ngx.exit(200);
     }
  }
--- request eval
["GET /", "GET /metrics"]
--- more_headers eval
["", "Host: metrics"]
--- error_code eval
[ 200, 200 ]
--- expected_response_body_like_multiple eval
[
"",
[
    qr/upstream_response_time_seconds(.|\n)/,
    qr/upstream_response_time_seconds_bucket\{service_id="",service_system_name="",le=".*"\} 1/,
    qr/upstream_status\{status="200",service_id="",service_system_name=""\} 1/
]]
--- no_error_log
[error]

=== TEST 5: the metrics endpoint shows request response times
--- configuration
{
  "services": [
    {
      "id": 42,
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
       ngx.exit(200);
     }
  }
--- request eval
["GET /", "GET /metrics"]
--- more_headers eval
["", "Host: metrics"]
--- error_code eval
[ 200, 200 ]
--- response_body_like eval
[
"",
qr/total_response_time_seconds(.|\n)*total_response_time_seconds_bucket\{service_id="",service_system_name="",le=".*"\} 1/
]
--- no_error_log
[error]



=== TEST 6: extended metrics show services id
--- env eval
("APICAST_EXTENDED_METRICS", "true")
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
       ngx.exit(200);
     }
  }

--- request eval
["GET /", "GET /metrics"]
--- more_headers eval
["", "Host: metrics"]
--- error_code eval
[ 200, 200 ]
--- expected_response_body_like_multiple eval
[
"",
[
    qr/total_response_time_seconds(.|\n)*/,
    qr/total_response_time_seconds_bucket\{service_id="42",service_system_name="foo",le=".*"\} 1/,
    qr/upstream_response_time_seconds(.|\n)*/,
    qr/upstream_response_time_seconds_bucket\{service_id="42",service_system_name="foo",le=".*"\} 1/,
    qr/upstream_status\{status="200",service_id="42",service_system_name="foo"\} 1/
]
]
--- no_error_log
[error]

=== TEST 7: extended metrics with multiple services
--- env eval
("APICAST_EXTENDED_METRICS", "true")
--- configuration
{
  "services": [
    {
      "id": 42,
      "system_name": "foo",
      "proxy": {
        "hosts": [
          "one"
        ],
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
    },
    {
      "id": 21,
      "system_name": "bar",
      "proxy": {
        "hosts": [
          "two"
        ],
        "policy_chain": [
          {
            "name": "apicast.policy.upstream",
            "configuration": {
              "rules": [
                {
                  "regex": "/",
                  "url": "http://test:$TEST_NGINX_SERVER_PORT/two"
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
       ngx.exit(200);
     }
  }

  location /two {
     content_by_lua_block {
       ngx.exit(200);
     }
  }
--- request eval
["GET /", "GET /two", "GET /metrics"]
--- more_headers eval
["Host: one", "Host: two", "Host: metrics"]
--- error_code eval
[ 200, 200, 200 ]
--- expected_response_body_like_multiple eval
[
"",
"",
[
qr/total_response_time_seconds_bucket\{service_id="42",service_system_name="foo",le=".*"\} 1/,
qr/upstream_response_time_seconds_bucket\{service_id="42",service_system_name="foo",le=".*"\} 1/,
qr/upstream_status\{status="200",service_id="42",service_system_name="foo"\} 1/,
qr/total_response_time_seconds_bucket\{service_id="21",service_system_name="bar",le=".*"\} 1/,
qr/upstream_response_time_seconds_bucket\{service_id="21",service_system_name="bar",le=".*"\} 1/,
qr/upstream_status\{status="200",service_id="21",service_system_name="bar"\} 1/
]]
--- no_error_log
[error]
