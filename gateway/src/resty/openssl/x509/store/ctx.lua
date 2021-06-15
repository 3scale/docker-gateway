local base = require('resty.openssl.base') local ffi = require('ffi')

ffi.cdef([[
// https://www.openssl.org/docs/man1.1.0/crypto/X509_STORE_CTX_init.html
int X509_STORE_CTX_init(X509_STORE_CTX *ctx, X509_STORE *store,
                        X509 *x509, const OPENSSL_STACK *chain);
void X509_STORE_CTX_cleanup(X509_STORE_CTX *ctx);
void X509_STORE_CTX_free(X509_STORE_CTX *ctx);
void X509_STORE_CTX_set0_param(X509_STORE_CTX *ctx, X509_VERIFY_PARAM *param);
X509_VERIFY_PARAM *X509_STORE_CTX_get0_param(X509_STORE_CTX *ctx);

int X509_verify_cert(X509_STORE_CTX *ctx);
int   X509_STORE_CTX_get_error(X509_STORE_CTX *ctx);

const char *X509_verify_cert_error_string(long n);
]])

local C = ffi.C
local ffi_assert = base.ffi_assert
local tocdata = base.tocdata
local openssl_error = base.openssl_error
local setmetatable = setmetatable

local _M = {}
local mt = { __index = _M }

local function new_ctx()
  local ctx = ffi_assert(C.X509_STORE_CTX_new())

  return ffi.gc(ctx, C.X509_STORE_CTX_free)
end

function _M:validate()
  local ctx = new_ctx()

  ffi_assert(C.X509_STORE_CTX_init(ctx, self.store, tocdata(self.x509), self.chain), 1)

  local ret = C.X509_verify_cert(ctx)

  if ret == 1 then
    return true
  else
    local err = ffi.string(C.X509_verify_cert_error_string(C.X509_STORE_CTX_get_error(ctx)))
    ngx.log(ngx.DEBUG, 'OpenSSL cert validation err: ', openssl_error())
    return false, err
  end
end

-- this could be optimized by reusing the context between validations,
-- but it is way harder to make safe when there are exceptions

function _M.new(store, x509, chain)
  return setmetatable({ store = store, x509 = x509, chain = chain }, mt)
end

return _M
