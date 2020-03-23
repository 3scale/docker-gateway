--- Basic Auth policy

local ipairs = ipairs
local type = type
local insert = table.insert

local TemplateString = require 'apicast.template_string'

local default_value_type = 'plain'

local policy = require('apicast.policy')
local _M = policy.new('Basic Auth Policy', 'builtin')

local new = _M.new

local b='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

function enc(data)
    return ((data:gsub('.', function(x) 
        local r,b='',x:byte()
        for i=8,1,-1 do r=r..(b%2^i-b%2^(i-1)>0 and '1' or '0') end
        return r;
    end)..'0000'):gsub('%d%d%d?%d?%d?%d?', function(x)
        if (#x < 6) then return '' end
        local c=0
        for i=1,6 do c=c+(x:sub(i,i)=='1' and 2^(6-i) or 0) end
        return b:sub(c+1,c+1)
    end)..({ '', '==', '=' })[#data%3+1])
end

local function set_request_header(header_name, value)
  ngx.req.set_header(header_name, value)
end

local function apply_auth_header(context, credentials, ...)
  local id = credentials["id"]
  local password = credentials["password"]
  local basic_auth_token = enc(id..":"..password)
  set_request_header("Authorization", "Basic "..basic_auth_token)
end

local function init_config(config)
  local res = config or {}
  res.credentials = res.credentials or {}
  return res
end

function _M.new(config)
  local self = new(config)
  self.config = init_config(config)
  return self
end

function _M:rewrite(context)
  apply_auth_header(context, self.config.credentials)
end

return _M
