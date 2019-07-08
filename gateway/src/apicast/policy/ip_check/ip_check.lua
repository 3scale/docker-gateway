local iputils = require("resty.iputils")
local ClientIP = require('apicast.policy.ip_check.client_ip')

local policy = require('apicast.policy')
local _M = policy.new('IP check policy', 'builtin')

local new = _M.new

local default_err_msg = 'IP address not allowed'
local default_client_ip_sources = { 'last_caller' }

local function parse_cidrs(cidrs)
  return iputils.parse_cidrs(cidrs or {})
end

local function ip_in_range(ip, cidrs)
  return iputils.ip_in_cidrs(ip, cidrs)
end

local function deny_request(error_msg)
  ngx.status = ngx.HTTP_FORBIDDEN
  ngx.say(error_msg)
  ngx.exit(ngx.status)
end

local function apply_whitelist(self, client_ip)
  if not ip_in_range(client_ip, self.ips) then
    deny_request(self.error_msg)
  end
end

local function apply_blacklist(self, client_ip)
  if ip_in_range(client_ip, self.ips) then
    deny_request(self.error_msg)
  end
end

local noop = function() end

local check_ip_function = {
  blacklist = apply_blacklist,
  whitelist = apply_whitelist
}

function _M.new(config)
  local self = new(config)

  local conf = config or {}

  self.ips = parse_cidrs(conf.ips) or {}
  self.error_msg = conf.error_msg or default_err_msg
  self.client_ip_sources = conf.client_ip_sources or default_client_ip_sources

  local check_type = conf.check_type
  self.check_client_ip = check_ip_function[check_type] or noop

  return self
end

function _M:access()
  local client_ip = ClientIP.get_from(self.client_ip_sources)

  if client_ip then
    self:check_client_ip(client_ip)
  end
end

return _M
