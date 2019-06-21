--- resty.ctx
-- Module for sharing ngx.ctx to subrequests.
-- @module resty.ctx

local ffi = require 'ffi'
local debug = require 'debug'
local base = require "resty.core.base"

-- to get FFI definitions
require 'resty.core.ctx'

local registry = debug.getregistry()
local getfenv = getfenv
local C = ffi.C
local FFI_NO_REQ_CTX = base.FFI_NO_REQ_CTX
local error = error
local tonumber = tonumber

local _M = {
}

local function __ngx_req()
  return getfenv(0).__ngx_req
end

local get_request = base.get_request or __ngx_req

--- Return ctx reference number
-- @raise no request found, no request ctx found
-- @treturn int
function _M.ref()
  local r = get_request()

  if not r then
    return error("no request found")
  end

  local _ = ngx.ctx -- load context

  local ctx_ref = C.ngx_http_lua_ffi_get_ctx_ref(r)

  if ctx_ref == FFI_NO_REQ_CTX then
    return error("no request ctx found")
  end

  -- The context should not be garbage collected until all the subrequests are completed.
  -- That includes internal redirects and post action.

  return ctx_ref
end

_M.var = 'ctx_ref'

--- Store ctx reference in ngx.var
-- @tparam ?string var variable name, defaults to ctx_ref
function _M.stash(var)
  ngx.var[var or _M.var] = _M.ref()
end

local function get_ctx(ref)
  local r = get_request()

  if not r then
    return error("no request found")
  end

  local ctx_ref = tonumber(ref)
  if not ctx_ref then
    return
  end

  return registry.ngx_lua_ctx_tables[ctx_ref] or error("no request ctx found")
end

--- Apply stored ctx to the current request
-- @tparam ?string var variable name, defaults to ctx_ref
-- @raise no request found
-- @treturn table
function _M.apply(var)
  local ctx = get_ctx(ngx.var[var or _M.var])

  -- this will actually store the reference again
  -- so each request that gets the context applied will hold own reference
  -- this is a very safe way to ensure it is not GC'd or released by another requests
  ngx.ctx = ctx

  return ctx
end

return _M
