use lib 't';
use Test::APIcast::Blackbox 'no_plan';

repeat_each(2);

run_tests();

__DATA__

=== TEST 1: Simple Websocket connection pass through
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
          "127.0.0.1"
        ],
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/",
        "proxy_rules": [
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 2 }
        ],
        "policy_chain": [
          {
            "name": "apicast",
            "version": "builtin",
            "configuration": {}
          },
          {
            "name": "websocket",
            "version": "builtin",
            "configuration": {}
          }
        ]
      }
    }
  ]
}
--- backend
location /transactions/authrep.xml {
  content_by_lua_block {
    ngx.exit(200)
  }
}
--- upstream env
location / {
  access_by_lua_block {
    local server = require "resty.websocket.server"

    local wb, err = server:new{
      timeout = 5000,  -- in milliseconds
      max_payload_len = 65535,
    }
    if not wb then
      ngx.log(ngx.ERR, "failed to new websocket: ", err)
      return ngx.exit(444)
    end

    local data, typ, err = wb:recv_frame()
    if not data then
      if not string.find(err, "timeout", 1, true) then
        ngx.log(ngx.ERR, "failed to receive a frame: ", err)
        return ngx.exit(444)
      end
    end

    bytes, err = wb:send_text("Data: "..data.." Type: "..typ)
    if not bytes then
      ngx.log(ngx.ERR, "failed to send a text frame: ", err)
      return ngx.exit(444)
    end
  }
}

--- test
content_by_lua_block {
  local client = require "resty.websocket.client"
  local wb, err = client:new()
  local server = ngx.var.server_addr
  local apicast_port = ngx.var.apicast_port
  local uri = "ws://"..server.. ":"..apicast_port.."/?user_key=foo"
  local ok, err = wb:connect(uri)
  if not ok then
    ngx.say("failed to connect: " .. err)
    return
  end

  local bytes, err = wb:send_text("Sending from client")
  if not bytes then
    ngx.say("failed to send frame: ", err)
    return
  end

  local data, typ, err = wb:recv_frame()
  if not data then
    ngx.say("failed to receive the frame: ",apicast_port, err)
    return
  end

  ngx.say("received: ", data)
}
--- response_body env
received: Data: Sending from client Type: text
--- error_code: 200
--- timeout: 10
--- no_error_log
[error]


=== TEST 2: No websocket connection with policy does not change Upgrade header
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
          "localhost"
        ],
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/",
        "proxy_rules": [
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 2 }
        ],
        "policy_chain": [
          {
            "name": "apicast",
            "version": "builtin",
            "configuration": {}
          },
          {
            "name": "websocket",
            "version": "builtin",
            "configuration": {}
          }
        ]
      }
    }
  ]
}
--- backend
location /transactions/authrep.xml {
  content_by_lua_block {
    ngx.exit(200)
  }
}
--- upstream env
location / {
  content_by_lua_block {
    local headers  = ngx.req.get_headers()
    assert(headers["Upgrade"] == nil)
  }
}
--- request
GET /?user_key=value
--- error_code: 200
--- no_error_log
[error]


=== TEST 3: Websocket using ws url in the api_backend
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
          "127.0.0.1"
        ],
        "api_backend": "ws://test:$TEST_NGINX_SERVER_PORT/",
        "proxy_rules": [
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 2 }
        ],
        "policy_chain": [
          {
            "name": "apicast",
            "version": "builtin",
            "configuration": {}
          },
          {
            "name": "websocket",
            "version": "builtin",
            "configuration": {}
          }
        ]
      }
    }
  ]
}
--- backend
location /transactions/authrep.xml {
  content_by_lua_block {
    ngx.exit(200)
  }
}
--- upstream env
location / {
  access_by_lua_block {
    local server = require "resty.websocket.server"

    local wb, err = server:new{
      timeout = 5000,  -- in milliseconds
      max_payload_len = 65535,
    }
    if not wb then
      ngx.log(ngx.ERR, "failed to new websocket: ", err)
      return ngx.exit(444)
    end

    local data, typ, err = wb:recv_frame()
    if not data then
      if not string.find(err, "timeout", 1, true) then
        ngx.log(ngx.ERR, "failed to receive a frame: ", err)
        return ngx.exit(444)
      end
    end

    bytes, err = wb:send_text("Data: "..data.." Type: "..typ)
    if not bytes then
      ngx.log(ngx.ERR, "failed to send a text frame: ", err)
      return ngx.exit(444)
    end
  }
}

--- test
content_by_lua_block {
  local client = require "resty.websocket.client"
  local wb, err = client:new()
  local server = ngx.var.server_addr
  local apicast_port = ngx.var.apicast_port
  local uri = "ws://"..server.. ":"..apicast_port.."/?user_key=foo"
  local ok, err = wb:connect(uri)
  if not ok then
    ngx.say("failed to connect: " .. err)
    return
  end

  local bytes, err = wb:send_text("Sending from client")
  if not bytes then
    ngx.say("failed to send frame: ", err)
    return
  end

  local data, typ, err = wb:recv_frame()
  if not data then
    ngx.say("failed to receive the frame: ",apicast_port, err)
    return
  end

  ngx.say("received: ", data)
}
--- response_body env
received: Data: Sending from client Type: text
--- error_code: 200
--- timeout: 10
--- no_error_log
[error]


=== TEST 2: No websocket connection with policy does not change Upgrade header
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
          "localhost"
        ],
        "api_backend": "http://test:$TEST_NGINX_SERVER_PORT/",
        "proxy_rules": [
          { "pattern": "/", "http_method": "GET", "metric_system_name": "hits", "delta": 2 }
        ],
        "policy_chain": [
          {
            "name": "apicast",
            "version": "builtin",
            "configuration": {}
          },
          {
            "name": "websocket",
            "version": "builtin",
            "configuration": {}
          }
        ]
      }
    }
  ]
}
--- backend
location /transactions/authrep.xml {
  content_by_lua_block {
    ngx.exit(200)
  }
}
--- upstream env
location / {
  content_by_lua_block {
    local headers  = ngx.req.get_headers()
    assert(headers["Upgrade"] == nil)
  }
}
--- request
GET /?user_key=value
--- error_code: 200
--- no_error_log
[error]
