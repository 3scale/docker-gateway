
local auto_ssl = (require "resty.auto-ssl").new()

local util = require('util')
local env = require('resty.env')


auto_ssl:set("allow_domain", function(domain)
  return true
end)

auto_ssl:set('dir', env.get('APICAST_SSL_STORAGE') or '/tmp')

local _M = {}

function _M:init()
	auto_ssl:init()
end

function _M:init_worker()
	auto_ssl:init_worker()
end

function _M:hook_server()
	auto_ssl:hook_server()
end

function _M:ssl_certificate()
	auto_ssl:ssl_certificate()
end

function _M:challenge_server()
	auto_ssl:challenge_server()
end

return _M
