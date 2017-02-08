use Test::Nginx::Socket::Lua 'no_plan';
use Cwd qw(cwd);

my $pwd = cwd();
my $apicast = $ENV{TEST_NGINX_APICAST_PATH} || "$pwd/apicast";

$ENV{TEST_NGINX_LUA_PATH} = "$apicast/src/?.lua;;";
$ENV{TEST_NGINX_BACKEND_CONFIG} = "$apicast/conf.d/backend.conf";
$ENV{TEST_NGINX_APICAST_CONFIG} = "$apicast/conf.d/apicast.conf";

log_level('debug');
repeat_each(2);
run_tests();

__DATA__

=== TEST 1: loading custom config file works
--- main_config
  env APICAST_CUSTOM_CONFIG=html/custom.lua;
--- http_config
  lua_package_path "$TEST_NGINX_LUA_PATH";
--- config
  location /t {
    content_by_lua_block {
      path = package.path
      require('proxy')
      assert(path == package.path)
      package.loaded.proxy = nil
      ngx.exit(ngx.HTTP_OK)
    }
  }
--- request
GET /t
--- user_files
>>> custom.lua
return { setup = function() print('loaded custom.lua') end }
--- error_log
loaded custom.lua
