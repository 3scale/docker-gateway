local errlog = require "ngx.errlog"
local base = require "resty.core.base"
local ffi = require 'ffi'

local C = ffi.C
local FFI_BAD_CONTEXT = base.FFI_BAD_CONTEXT
local find = string.find
local getinfo = debug.getinfo
local reverse = string.reverse
local select = select
local sub = string.sub
local tostring = tostring

local get_request = base.get_request


ffi.cdef[[
int ngx_http_lua_ffi_get_phase(ngx_http_request_t *r, char **err)
]]

local _M = {}

local function get_prefix_from_info(info)
  local reverse_str = reverse(info.short_src)
  local first_match = find(reverse_str, "/")
  if not first_match  then
    return info.short_src
  end
  local reverse_filename = sub(reverse_str, 0, first_match - 1)

  local result = string.reverse(reverse_filename) .. ":" .. info.currentline

  -- If the function name is present, just append to the prefix.
  if info.name then
    result = result .. ": " .. info.name .. "()"
  end
  return result
end

-- is_valid_request returns true if is a request. base.get_request returns a
-- request on init_worker and timer phases, so we need to validate that a valid
-- request is made.
local function is_valid_request()
  local r = get_request()
  if not r then
    return nil
  end

  local id = C.ngx_http_lua_ffi_req_get_method(r)
  return id ~= FFI_BAD_CONTEXT

end

local function send_log(level, msg, ...)
  local suffix = ""

  -- Only append the request_id if it's a request, if not will raise an
  -- exception.
  if is_valid_request() then
    suffix =  ", requestID=" .. ngx.var.request_id
  end

  local prefix = get_prefix_from_info(getinfo(2, "Snl")) .. ": "
  local n = select("#", ...)
  if n>0 then
    for i=1,n do
      msg = msg .. tostring(select(i, ...))
    end
  end

  local final_message = prefix .. msg .. suffix

  errlog.raw_log(level, final_message)
end

_M.log = send_log

function _M:patch_ngx_log()
  ngx.log = send_log
end

function _M:patch_ngx_log_on_debug()
  local log_level = errlog.get_sys_filter_level()
  if log_level == ngx.DEBUG then
    self:patch_ngx_log()
  end
end

return _M
