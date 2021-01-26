use lib 't';
use Test::APIcast::Blackbox 'no_plan';

$ENV{TEST_NGINX_HTML_DIR} ||= "$Test::Nginx::Util::ServRoot/html";

run_tests();

__DATA__

=== TEST 1: Routing policy with owner id reported correctly
--- backend
  location /transactions/authrep.xml {
    content_by_lua_block {
      -- request should not be here, is using batcher.
      ngx.exit(503)
    }
  }

  location /transactions/authorize.xml {
    content_by_lua_block {
      if not ngx.shared.test_counter then
        ngx.shared.test_counter = {}
      end

      local args = ngx.req.get_uri_args()

      local function validate_key(key, args)
        if not args[key] then
          return
        end
        local key_test_counter = ngx.shared.test_counter[key] or 0
        if key_test_counter == 0 then
          ngx.shared.test_counter[key] = key_test_counter + 1
          ngx.exit(200)
        else
          ngx.log(ngx.ERR, 'auth should be cached but called backend anyway')
          ngx.exit(502)
        end
      end
      validate_key("usage[test]", args)
      validate_key("usage[hits]", args)
    }
  }

  location /transactions.xml {
    content_by_lua_block {
      ngx.req.read_body()
      local post_args = ngx.req.get_post_args()
      require('luassert').same(post_args["transactions[0][usage][hits]"], "3")
      require('luassert').same(post_args["transactions[0][usage][test]"], "1")
      ngx.exit(200)
    }
  }

--- upstream
  location ~* /second/foo/bar {
    content_by_lua_block {
      ngx.say('yay, api backend');
    }
  }

  location ~* /one/foo {
    content_by_lua_block {
      ngx.say('yay, api backend');
    }
  }
--- configuration
{
  "services": [
    {
      "id": 42,
      "backend_version": 1,
      "backend_authentication_type": "service_token",
      "backend_authentication_value": "token-value",
      "proxy": {
        "policy_chain": [
          {
            "name": "apicast.policy.routing",
            "configuration": {
              "rules": [
                {
                  "url": "http://test:$TEST_NGINX_SERVER_PORT/second/",
                  "owner_id": 4,
                  "condition": {
                    "operations": [
                      {
                        "match": "path",
                        "op": "matches",
                        "value": "/foo/bar"
                      }
                    ]
                  }
                },
                {
                  "url": "http://test:$TEST_NGINX_SERVER_PORT/one/",
                  "owner_id": 3,
                  "condition": {
                    "operations": [
                      {
                        "match": "path",
                        "op": "matches",
                        "value": "/foo"
                      }
                    ]
                  }
                }
              ]
            }
          },
          {
            "name": "apicast.policy.3scale_batcher",
            "configuration": {
              "batch_report_seconds" : 1
            }
          },
          {
            "name": "apicast.policy.apicast"
          }
        ],
        "proxy_rules": [
          {
            "pattern": "/foo/bar",
            "http_method": "GET",
            "metric_system_name": "hits",
            "delta": 1,
            "owner_id": 4,
            "owner_type": "BackendApi"
          },
          {
            "pattern": "/foo",
            "http_method": "GET",
            "metric_system_name": "test",
            "delta": 1,
            "owner_id": 3,
            "owner_type": "BackendApi"
          }
        ]
      }
    }
  ]
}
--- test env
content_by_lua_block {
  local function request(path)
    local sock = ngx.socket.tcp()
    sock:settimeout(2000)

    local ok, err = sock:connect(ngx.var.server_addr, ngx.var.apicast_port)
    if not ok then
        ngx.say("failed to connect: ", err)
        return
    end

    ngx.say("connected: ", ok)

    sock:send("GET " .. path .. "?user_key=123 HTTP/1.1\r\nHost: localhost\r\n\r\n")
    local data = sock:receive()
    ngx.say(data)
  end

  request('/foo/bar')
  request('/foo/bar')
  request('/foo/bar')

  request('/foo')
  ngx.sleep(2)
}
--- response_body
connected: 1
HTTP/1.1 200 OK
connected: 1
HTTP/1.1 200 OK
connected: 1
HTTP/1.1 200 OK
connected: 1
HTTP/1.1 200 OK
--- error_code: 200
--- no_error_log
[error]


=== TEST 2: Batching policy returns no mapping rule found correctly
--- backend
  location /transactions/authrep.xml {
    content_by_lua_block {
      -- request should not be here, is using batcher.
      ngx.exit(503)
    }
  }

  location /transactions/authorize.xml {
    content_by_lua_block {
      ngx.say("ok")
    }
  }

  location /transactions.xml {
    content_by_lua_block {
      ngx.say("ok")
    }
  }
--- upstream
  location ~* /second/foo/bar {
    content_by_lua_block {
      ngx.say('yay, api backend');
    }
  }
--- configuration
{
  "services": [
    {
      "id": 42,
      "backend_version": 1,
      "backend_authentication_type": "service_token",
      "backend_authentication_value": "token-value",
      "proxy": {
        "policy_chain": [
          {
            "name": "apicast.policy.routing",
            "configuration": {
              "rules": [
                {
                  "url": "http://test:$TEST_NGINX_SERVER_PORT/second/",
                  "owner_id": 4,
                  "condition": {
                    "operations": [
                      {
                        "match": "path",
                        "op": "matches",
                        "value": "/foo/bar"
                      }
                    ]
                  }
                }
              ]
            }
          },
          {
            "name": "apicast.policy.3scale_batcher",
            "configuration": {
              "batch_report_seconds" : 1
            }
          },
          {
            "name": "apicast.policy.apicast"
          }
        ],
        "proxy_rules": [
          {
            "pattern": "/foo/bar",
            "http_method": "GET",
            "metric_system_name": "hits",
            "delta": 1,
            "owner_id": 4,
            "owner_type": "BackendApi"
          }
        ]
      }
    }
  ]
}
--- request eval
["GET /?user_key=value", "GET /foo/bar?user_key=value"]
--- response_body chomp eval
["No Mapping Rule matched", "yay, api backend\n"]
--- error_code eval
[404, 200]
--- no_error_log
[error]
