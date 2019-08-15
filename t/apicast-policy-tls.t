use lib 't';
use Test::APIcast::Blackbox 'no_plan';

$ENV{TEST_NGINX_HTML_DIR} ||= "$Test::Nginx::Util::ServRoot/html";

run_tests();

__DATA__

=== TEST 1: tls accepts configuration
--- env eval
(
    'APICAST_HTTPS_PORT' => "$Test::Nginx::Util::ServerPortForClient",
)
--- configuration
{
  "services": [
    {
      "proxy": {
        "policy_chain": [
          {
            "name": "apicast.policy.tls",
            "configuration": {
              "certificates": [
                {
                  "certificate_path": "$TEST_NGINX_HTML_DIR/server.crt",
                  "certificate_key_path": "$TEST_NGINX_HTML_DIR/server.key"
                }
              ]
            }
          },
          {
            "name": "apicast.policy.upstream",
            "configuration": {
              "rules": [
                {
                  "regex": "/",
                  "url": "http://echo"
                }
              ]
            }
          }
        ]
      }
    }
  ]
}
--- test env
lua_ssl_trusted_certificate $TEST_NGINX_HTML_DIR/server.crt;
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

    local sess, err = sock:sslhandshake(nil, "localhost", true)
    if not sess then
        ngx.say("failed to do SSL handshake: ", err)
        return
    end

    ngx.say("ssl handshake: ", type(sess))
    sock:send("GET " .. path .. "?user_key=123 HTTP/1.1\r\nHost: localhost\r\n\r\n")
    local data = sock:receive()
    ngx.say(data)
  end

  request('/')
}
--- response_body
connected: 1
ssl handshake: userdata
HTTP/1.1 200 OK
--- no_error_log
[error]
--- user_files
>>> server.crt
-----BEGIN CERTIFICATE-----
MIIBRzCB7gIJAPHi8uNGM8wDMAoGCCqGSM49BAMCMCwxFjAUBgNVBAoMDVRlc3Q6
OkFQSWNhc3QxEjAQBgNVBAMMCWxvY2FsaG9zdDAeFw0xODA2MDUwOTQ0MjRaFw0y
ODA2MDIwOTQ0MjRaMCwxFjAUBgNVBAoMDVRlc3Q6OkFQSWNhc3QxEjAQBgNVBAMM
CWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABI3IZUvpJsaQbiLy
/yfthJDd/+BIaKzAbgMAimth4ePOi3a/YICwsHyq6sBxbgvMeTwxNJIHpe3td4tB
VZ5Wr10wCgYIKoZIzj0EAwIDSAAwRQIhAPRkfbxowt0H7p5xZYpwoMKanUXz9eKQ
0sGkOw+TqqGXAiAMKJRqtjnCF2LIjGygHG6BlgjM4NgIMDHteZPEr4qEmw==
-----END CERTIFICATE-----
>>> server.key
-----BEGIN EC PARAMETERS-----
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIH22v43xtXcHWJyH3BEB9N30ahrCOLripkoSWW/WujUxoAoGCCqGSM49
AwEHoUQDQgAEjchlS+kmxpBuIvL/J+2EkN3/4EhorMBuAwCKa2Hh486Ldr9ggLCw
fKrqwHFuC8x5PDE0kgel7e13i0FVnlavXQ==
-----END EC PRIVATE KEY-----


=== TEST 2: tls failed on invalid certificate.
--- env eval
(
    'APICAST_HTTPS_PORT' => "$Test::Nginx::Util::ServerPortForClient",
)
--- configuration
{
  "services": [
    {
      "proxy": {
        "policy_chain": [
          {
            "name": "apicast.policy.tls",
            "configuration": {
              "certificates": [
                {
                  "certificate_path": "$TEST_NGINX_HTML_DIR/server_invalid.crt",
                  "certificate_key_path": "$TEST_NGINX_HTML_DIR/server.key"
                }
              ]
            }
          },
          {
            "name": "apicast.policy.upstream",
            "configuration": {
              "rules": [
                {
                  "regex": "/",
                  "url": "http://echo"
                }
              ]
            }
          }
        ]
      }
    }
  ]
}
--- test env
lua_ssl_trusted_certificate $TEST_NGINX_HTML_DIR/server.crt;
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

    local sess, err = sock:sslhandshake(nil, "localhost", true)
    if not sess then
        ngx.say("failed to do SSL handshake: ", err)
        return
    end

    ngx.say("ssl handshake: ", type(sess))
    sock:send("GET " .. path .. "?user_key=123 HTTP/1.1\r\nHost: localhost\r\n\r\n")
    local data = sock:receive()
    ngx.say(data)
  end

  request('/')
}
--- response_body
connected: 1
failed to do SSL handshake: handshake failed
--- error_log
ssl3_read_bytes:sslv3 alert handshake failure:SSL
sslv3 alert handshake failure
--- user_files
>>> server_invalid.crt
-----BEGIN CERTIFICATE-----
MIID1zCCAr8CFFIaIIw9n2Afgxf7IvPTRDdweQnFMA0GCSqGSIb3DQEBCwUAMEIx
CzAJBgNVBAYTAlhYMRUwEwYDVQQHDAxEZWZhdWx0IENpdHkxHDAaBgNVBAoME0Rl
ZmF1bHQgQ29tcGFueSBMdGQwHhcNMTkwODE1MDYyMDU2WhcNMjAxMjI3MDYyMDU2
WjAOMQwwCgYDVQQDDANvbmUwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoIC
AQDF9a4UJKH2CDKKPMcfRGZnajvr2Wp8Xm6QEr5/L2XzioWx+ciahI0IJN4D1KpK
dlYBUbKfn3UK1t+EMdXiq00Z9Mh3FTns9qGwHP/ESFmVikJIvU+PpFqQurA97s0J
hdXAL+S0GW6Z9DQezIK/UAw89GvR79JZO7kN+HMMqtGH3Ze3D6oH+muhDzXePRPb
kV+VYYVJmjIpgY4e/SJT7cHLlzkzCEkqJK2kQF49qPUCY5/entum0mL2diui4Ohn
CTGZ3oWyfEeifBJjnMNdA+N1Fmo5Npqye2NTLA3H0Yu/jdml2JAeDgq5c4JDxDNz
c1KKaVwGCf7YzpKO8MDHUUUACwatyb0r/7RoLaeQq0SBemrTcUOEp8cjZ0Og3dAv
XVCjYAg8ldSvFyxddKkKguyNe34J66iu0GT15UQXDgFlhERYXmf0vcH4maGh1von
Gije2Fo2UuxWWvJLwUrTYQRLUxovCEbRgVK6vibsjiadGZkkUQZonm8j+CsHZ4w6
y5JE4DzUoT7yEm0QQfN0bpnuf/0bmGZKfxLcvZaZvEyw2StW8NzC1JKcHFtgLiLX
3TnFw4fJqQqRB9kGh8KWHc1cIcejqXysz/NYYp4Hdmmm9e142NVuObSwTwdBeeUp
RcBK2RWvqPfWfSom+hXosRQbhOnT6rL+VvRCUSlNbut0SQIDAQABMA0GCSqGSIb3
DQEBCwUAA4IBAQAgY6VR9nmSklWvHHffywslIGJSiB25cnh39Olx6puJU9Wd/r5E
IO6XoXaU72XzdBCQGz79KBKW1FEUyAX46+JUDlGkXA48vHdUemMrrx6VGHyv683C
6EsZXTBE5JTlRSYFJyhnqk0E/UkfXGtnnB41udXMlOXdrJeVbbqfmbqypKofUMBm
UYdKCFje7XaOgQfYwoF5+f7/cWXhe3j+ooepc57pF8T75Vq1g3B69KwC6LdCSPp+
0HaHdAoJb8hRIQjbL4yjXtrphH7r8xp8bEUGVHz/K0X3ZTEGXRVB5xAc9jgX/3O6
+MVJbivfKK5unRP6S0WvjFg5x3hc1yBzR3/X
-----END CERTIFICATE-----
>>> server.crt
-----BEGIN CERTIFICATE-----
MIIBRzCB7gIJAPHi8uNGM8wDMAoGCCqGSM49BAMCMCwxFjAUBgNVBAoMDVRlc3Q6
OkFQSWNhc3QxEjAQBgNVBAMMCWxvY2FsaG9zdDAeFw0xODA2MDUwOTQ0MjRaFw0y
ODA2MDIwOTQ0MjRaMCwxFjAUBgNVBAoMDVRlc3Q6OkFQSWNhc3QxEjAQBgNVBAMM
CWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABI3IZUvpJsaQbiLy
/yfthJDd/+BIaKzAbgMAimth4ePOi3a/YICwsHyq6sBxbgvMeTwxNJIHpe3td4tB
VZ5Wr10wCgYIKoZIzj0EAwIDSAAwRQIhAPRkfbxowt0H7p5xZYpwoMKanUXz9eKQ
0sGkOw+TqqGXAiAMKJRqtjnCF2LIjGygHG6BlgjM4NgIMDHteZPEr4qEmw==
-----END CERTIFICATE-----
>>> server.key
-----BEGIN EC PARAMETERS-----
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIH22v43xtXcHWJyH3BEB9N30ahrCOLripkoSWW/WujUxoAoGCCqGSM49
AwEHoUQDQgAEjchlS+kmxpBuIvL/J+2EkN3/4EhorMBuAwCKa2Hh486Ldr9ggLCw
fKrqwHFuC8x5PDE0kgel7e13i0FVnlavXQ==
-----END EC PRIVATE KEY-----
