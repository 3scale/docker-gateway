use lib 't';
use Test::APIcast::Blackbox 'no_plan';

# These test are a bit difficult to understand. Due to the Nginx is set to listen
# proxy_protocol, all backends upstream need to use another port, if not the
# backend client and API will fail, this is why a new server is added on
# --backend test section
#
# Additionally, this is the reason why the IP Check policy is tested here.


require("policies.pl");
repeat_each(3);
$ENV{TEST_NGINX_HTML_DIR} ||= "$Test::Nginx::Util::ServRoot/html";
run_tests();

__DATA__

=== TEST 1: Simple proxy-procol connection
--- init eval
$Test::Nginx::Util::BACKEND_PORT = Test::APIcast::get_random_port();
--- env eval
(
  "BACKEND_ENDPOINT_OVERRIDE"=> "http://127.0.0.1:$Test::Nginx::Util::BACKEND_PORT",
  "APICAST_HTTP_PROXY_PROTOCOL" => "true"
)
--- configuration eval
<<EOF
{
  "services": [
    {
      "id": 42,
      "backend_version":  1,
      "backend_authentication_type": "service_token",
      "backend_authentication_value": "token-value",
      "proxy": {
        "hosts": [
          "localhost"
        ],
        "api_backend": "http://127.0.0.1:$Test::Nginx::Util::BACKEND_PORT/",
        "proxy_rules": [
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 1 }
        ],
        "policy_chain": [
          {
            "name": "apicast",
            "version": "builtin",
            "configuration": {}
          }
        ]
      }
    }
  ]
}
EOF
--- backend eval
<<EOF
}
server {
  listen $Test::Nginx::Util::BACKEND_PORT;
  server_name _ default_server;
  location /transactions/authrep.xml {
    content_by_lua_block {
      ngx.exit(200)
    }
  }

  location /foo {
    access_by_lua_block {
        ngx.say("API BACKEND")
    }
  }
EOF
--- test env
content_by_lua_block {
    local sock = ngx.socket.tcp()
    sock:settimeout(2000)

    local ok, err = sock:connect(ngx.var.server_addr, ngx.var.apicast_port)
    if not ok then
        ngx.say("failed to connect: ", err)
        return
    end

    ngx.say("connected: ", ok)
    sock:send(string.format("PROXY TCP4 127.0.0.1 %s %s %s\r\n\r\n\r\n", ngx.var.server_addr, "10000", ngx.var.apicast_port)) 
    sock:send("GET /foo?user_key=123 HTTP/1.1\r\nHost: localhost\r\n\r\n")

    local data = sock:receive()
    ngx.say(data)
}
--- response_body env
connected: 1
HTTP/1.1 200 OK
--- error_code: 200
--- no_error_log
[error]


=== TEST 2: Simple IP check policy using proxy_protocol
--- init eval
$Test::Nginx::Util::BACKEND_PORT = Test::APIcast::get_random_port();
--- env eval
(
  "BACKEND_ENDPOINT_OVERRIDE"=> "http://127.0.0.1:$Test::Nginx::Util::BACKEND_PORT",
  "APICAST_HTTP_PROXY_PROTOCOL" => "true"
)
--- configuration eval
<<EOF
{
  "services": [
    {
      "id": 42,
      "backend_version":  1,
      "backend_authentication_type": "service_token",
      "backend_authentication_value": "token-value",
      "proxy": {
        "hosts": [
          "localhost"
        ],
        "api_backend": "http://127.0.0.1:$Test::Nginx::Util::BACKEND_PORT/",
        "proxy_rules": [
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 1 }
        ],
        "policy_chain": [
          {
            "name": "apicast.policy.ip_check",
            "configuration": {
              "ips": [ "9.9.9.9" ],
              "client_ip_sources": [
                "proxy_protocol_addr"
              ],
              "check_type": "blacklist",
              "error_msg": "A custom error message"
            }
          },
          {
            "name": "apicast",
            "version": "builtin",
            "configuration": {}
          }
        ]
      }
    }
  ]
}
EOF
--- backend eval
<<EOF
}
server {
  listen $Test::Nginx::Util::BACKEND_PORT;
  server_name _ default_server;
  location /transactions/authrep.xml {
    content_by_lua_block {
      ngx.exit(200)
    }
  }

  location /foo {
    access_by_lua_block {
        ngx.say("API BACKEND")
    }
  }
EOF
--- test env
content_by_lua_block {
    local sock = ngx.socket.tcp()
    sock:settimeout(2000)

    local ok, err = sock:connect(ngx.var.server_addr, ngx.var.apicast_port)
    if not ok then
        ngx.say("failed to connect: ", err)
        return
    end

    ngx.say("connected: ", ok)
    sock:send(string.format("PROXY TCP4 9.9.9.9 %s %s %s\r\n\r\n\r\n", ngx.var.server_addr, "10000", ngx.var.apicast_port))
    sock:send("GET /foo?user_key=123 HTTP/1.1\r\nHost: localhost\r\n\r\n")

    local data = sock:receive()
    ngx.say(data)
}
--- response_body env
connected: 1
HTTP/1.1 403 Forbidden
--- error_code: 200
--- no_error_log
[error]
