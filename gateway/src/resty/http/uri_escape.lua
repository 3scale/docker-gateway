
local ffi = require "ffi"

local C = ffi.C
local ffi_str = ffi.string

ffi.cdef[[
  uintptr_t ngx_escape_uri(unsigned char *dst, unsigned char *src, size_t size, unsigned int type);
]]

local ngx_escape_uri = C.ngx_escape_uri

local _M = { }


function _M.escape_uri(source_uri)
  if not source_uri then
    return ""
  end

  local source_uri_len = #source_uri

  local source_str = ffi.new("unsigned char[?]", source_uri_len + 1)
  ffi.copy(source_str, source_uri)

  -- If destination is NUL ngx_escape_uri returns the number of characters that
  -- are going to be escaped, need to calculate first to make sure to
  -- allocate the right amount of memory.
  local escape_len = 2 * ngx_escape_uri(nil, source_str, source_uri_len, 0)

  local dst = ffi.new("unsigned char[?]", source_uri_len + 1 + tonumber(escape_len))
  ngx_escape_uri(dst, source_str, source_uri_len, 0)
  return ffi_str(dst) 
end

return _M
