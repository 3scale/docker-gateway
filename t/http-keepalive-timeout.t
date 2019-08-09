use lib 't';
use Test::APIcast::Blackbox 'no_plan';

repeat_each(1);

run_tests();

__DATA__

=== TEST 1: Keepalive is not set if no env variable
--- configuration
{
  "services": [
    {
      "id": 42,
      "backend_version":  1,
      "backend_authentication_type": "service_token",
      "backend_authentication_value": "token-value",
      "proxy": {
        "hosts": [
          "one"
        ],
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
--- upstream env
  location / {
     content_by_lua_block {
       ngx.say('yay, api backend');
     }
  }
--- backend
  location /transactions/authrep.xml {
    content_by_lua_block {
      ngx.exit(200)
    }
  }
--- test env
content_by_lua_block {
  local sock = ngx.socket.tcp()
  local ok, err = sock:connect(ngx.var.server_addr, ngx.var.apicast_port)
  if not ok then
    ngx.say("failed to connect: ", err)
    ngx.exit(400)
    return
  end

  local function send_request(sock)
    local bytes, err = sock:send("GET /?user_key=foo HTTP/1.1\r\nHost:one\r\n\r\n")
    if not bytes then
      return false, string.format("failed to send bytes: %s", err)
    end

    local data, err = sock:receiveany(10 * 1024) -- read any data, at most 10K
    if not data then
      return false, string.format("failed to receive data: %s", err)
    end

    return true, nil
  end

  local result, err = send_request(sock)
  ngx.say("First request status: ", result, " err:", err)
  ngx.sleep(1)
  local result, err = send_request(sock)
  ngx.say("Second request status: ", result, " err:", err)
}
--- response_body
First request status: true err:nil
Second request status: true err:nil
--- no_error_log
[error]

=== TEST 2: Keepalive timeout cleans correctly on timeout.
--- env eval
("HTTP_KEEPALIVE_TIMEOUT", "0")
--- configuration
{
  "services": [
    {
      "id": 42,
      "backend_version":  1,
      "backend_authentication_type": "service_token",
      "backend_authentication_value": "token-value",
      "proxy": {
        "hosts": [
          "one"
        ],
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
--- upstream env
  location / {
     content_by_lua_block {
       ngx.say('yay, api backend');
     }
  }
--- backend
  location /transactions/authrep.xml {
    content_by_lua_block {
      ngx.exit(200)
    }
  }
--- test env
content_by_lua_block {
  local sock = ngx.socket.tcp()
  local ok, err = sock:connect(ngx.var.server_addr, ngx.var.apicast_port)
  if not ok then
    ngx.say("failed to connect: ", err)
    ngx.exit(400)
    return
  end

  local function send_request(sock)
    local bytes, err = sock:send("GET /?user_key=foo HTTP/1.1\r\nHost:one\r\n\r\n")
    if not bytes then
      return false, string.format("failed to send bytes: %s", err)
    end

    local data, err = sock:receiveany(10 * 1024) -- read any data, at most 10K
    if not data then
      return false, string.format("failed to receive data: %s", err)
    end

    return true, nil
  end

  local result, err = send_request(sock)
  ngx.say("First request status: ", result, " err:", err)
  ngx.sleep(1)

  result, err = send_request(sock)
  ngx.say("Second request status: ", result, " err:", err)
}
--- response_body
First request status: true err:nil
Second request status: false err:failed to receive data: closed
--- no_error_log
[error]

=== TEST 3: Keepalive timeout can be set correctly.
--- env eval
(
 "HTTP_KEEPALIVE_TIMEOUT" => 2
)
--- timeout: 10s
--- configuration
{
  "services": [
    {
      "id": 42,
      "backend_version":  1,
      "backend_authentication_type": "service_token",
      "backend_authentication_value": "token-value",
      "proxy": {
        "hosts": [
          "one"
        ],
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
--- upstream env
  location / {
     content_by_lua_block {
       ngx.say('yay, api backend');
     }
  }
--- backend
  location /transactions/authrep.xml {
    content_by_lua_block {
      ngx.exit(200)
    }
  }
--- test env
content_by_lua_block {
  local sock = ngx.socket.tcp()
  local ok, err = sock:connect(ngx.var.server_addr, ngx.var.apicast_port)
  if not ok then
    ngx.say("failed to connect: ", err)
    ngx.exit(400)
    return
  end

  local function send_request(sock)
    local bytes, err = sock:send("GET /?user_key=foo HTTP/1.1\r\nHost:one\r\n\r\n")
    if not bytes then
      return false, string.format("failed to send bytes: %s", err)
    end

    local data, err = sock:receiveany(10 * 1024) -- read any data, at most 10K
    if not data then
      return false, string.format("failed to receive data: %s", err)
    end

    return true, nil
  end

  local result, err = send_request(sock)
  ngx.say("First request status: ", result, " err:", err)
  ngx.sleep(1)
  result, err = send_request(sock)
  ngx.say("Second request status: ", result, " err:", err)

  ngx.sleep(3)
  result, err = send_request(sock)
  ngx.say("Third request status: ", result, " err:", err)
}
--- response_body
First request status: true err:nil
Second request status: true err:nil
Third request status: false err:failed to receive data: closed
--- no_error_log
[error]
