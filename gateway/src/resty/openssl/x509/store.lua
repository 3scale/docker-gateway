local base = require('resty.openssl.base')
local X509_STORE_CTX = require('resty.openssl.x509.store.ctx')
local ffi = require('ffi')

ffi.cdef([[
// https://www.openssl.org/docs/man1.1.0/crypto/X509_STORE_new.html
X509_STORE *X509_STORE_new(void);
void X509_STORE_free(X509_STORE *v);
int X509_STORE_lock(X509_STORE *v);
int X509_STORE_unlock(X509_STORE *v);
int X509_STORE_up_ref(X509_STORE *v);

// https://www.openssl.org/docs/man1.1.1/man3/X509_STORE_add_cert.html
int X509_STORE_add_cert(X509_STORE *store, X509 *x);
int X509_STORE_add_crl(X509_STORE *ctx, X509_CRL *x);
int X509_STORE_set_depth(X509_STORE *store, int depth);
int X509_STORE_set_flags(X509_STORE *ctx, unsigned long flags);
int X509_STORE_set_purpose(X509_STORE *ctx, int purpose);
int X509_STORE_set_trust(X509_STORE *ctx, int trust);

// https://www.openssl.org/docs/man1.1.0/crypto/X509_STORE_set1_param.html
int X509_STORE_set1_param(X509_STORE *store, X509_VERIFY_PARAM *pm);
X509_VERIFY_PARAM *X509_STORE_get0_param(X509_STORE *ctx);

// https://www.openssl.org/docs/man1.1.0/crypto/X509_STORE_CTX_set0_param.html
X509_VERIFY_PARAM *X509_VERIFY_PARAM_new(void);
int X509_VERIFY_PARAM_set_flags(X509_VERIFY_PARAM *param,
                                unsigned long flags);
void X509_VERIFY_PARAM_set_time(X509_VERIFY_PARAM *param, time_t t);
time_t X509_VERIFY_PARAM_get_time(const X509_VERIFY_PARAM *param);
void X509_VERIFY_PARAM_free(X509_VERIFY_PARAM *param);

// https://www.openssl.org/docs/man1.1.1/man3/X509_VERIFY_PARAM_set_depth.html
]])

local C = ffi.C
local ffi_assert = base.ffi_assert
local tocdata = base.tocdata

local X509_V_FLAG_PARTIAL_CHAIN = 0x80000

local function X509_VERIFY_PARAM(flags)
  local verify_param = ffi_assert(C.X509_VERIFY_PARAM_new())

  -- https://www.openssl.org/docs/man1.1.0/crypto/X509_VERIFY_PARAM_get_depth.html#example
  ffi_assert(C.X509_VERIFY_PARAM_set_flags(verify_param, flags))

  return ffi.gc(verify_param, C.X509_VERIFY_PARAM_free)
end

local _M = {}
local mt = { __index = _M }

function _M:add_cert(x509)
  return ffi_assert(C.X509_STORE_add_cert(self.store, tocdata(x509)))
end

function _M:validate_cert(x509, chain)
  local ctx = X509_STORE_CTX.new(self.store, x509, chain)

  return ctx:validate()
end

function _M:set_time(seconds)
  local verify_param = ffi_assert(C.X509_STORE_get0_param(self.store))
  C.X509_VERIFY_PARAM_set_time(verify_param, seconds)
end

function _M:time()
  local verify_param = ffi_assert(C.X509_STORE_get0_param(self.store))
  return C.X509_VERIFY_PARAM_get_time(verify_param)
end

function _M.new()
  local store = ffi_assert(C.X509_STORE_new())

  -- @TODO cleanup here
  -- ffi_gc(store, C.X509_STORE_free)
  -- enabling partial chains allows us to trust leaf certificates
  local verify_param = X509_VERIFY_PARAM(X509_V_FLAG_PARTIAL_CHAIN)

  ffi_assert(C.X509_STORE_set1_param(store, verify_param),1)
  
  local self = setmetatable({
    store = store,
  }, mt)
  return self
end

return _M
