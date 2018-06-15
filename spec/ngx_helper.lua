local busted = require('busted')
local misc = require('resty.core.misc')
local deepcopy = require('pl.tablex').deepcopy

local pairs = pairs

local ngx_var_original = deepcopy(ngx.var)
local ngx_ctx_original = deepcopy(ngx.ctx)
local ngx_shared_original = deepcopy(ngx.shared)
local ngx_header_original = deepcopy(ngx.header)

local register_getter = misc.register_ngx_magic_key_getter
local register_setter = misc.register_ngx_magic_key_setter

local function getlocal(fn, var)
  local i = 1
  while true do
    local name, val = debug.getupvalue(fn, i)
    if name == var then
      return val
    elseif not name then
      break
    end
    i = i + 1
  end
end

local get_status = getlocal(register_getter, 'ngx_magic_key_getters').status
local set_status = getlocal(register_setter, 'ngx_magic_key_setters').status
local get_headers_sent = getlocal(register_getter, 'ngx_magic_key_getters').headers_sent
local set_headers_sent = getlocal(register_setter, 'ngx_magic_key_setters').headers_sent

local function reset_ngx_shared(state)
  local shared = ngx.shared

  for name, dict in pairs(state) do
    shared[name] = dict
  end

  for name, dict in pairs(shared) do
    shared[name] = state[name]
  end
end

local function reset_ngx_state()
  ngx.var = deepcopy(ngx_var_original)
  ngx.ctx = deepcopy(ngx_ctx_original)
  ngx.header = deepcopy(ngx_header_original)

  reset_ngx_shared(ngx_shared_original)
end

local function cleanup()
  register_getter('status', get_status)
  register_setter('status', set_status)
  register_getter('headers_sent', get_headers_sent)
  register_setter('headers_sent', set_headers_sent)
  reset_ngx_state()
end

local function setup()
  -- Register getters and setters for ngx vars used in the tests.

  local status, headers_sent

  register_setter('status', function(newstatus)
    status = newstatus
  end)

  register_getter('status', function() return status end)

  register_setter('headers_sent', function(new_headers_sent)
    headers_sent = new_headers_sent
  end)

  register_getter('headers_sent', function() return headers_sent end)
end

busted.after_each(cleanup)
busted.teardown(cleanup)

busted.before_each(setup)
