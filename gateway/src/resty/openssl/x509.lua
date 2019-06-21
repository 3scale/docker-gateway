local base = require('resty.openssl.base')
local BIO = require('resty.openssl.bio')
local X509_NAME = require('resty.openssl.x509.name')
local EVP_MD = require('resty.openssl.evp')
local resty_str = require('resty.string')
local ffi = require('ffi')
local re_gsub = ngx.re.gsub

ffi.cdef([[
int OPENSSL_sk_num(const OPENSSL_STACK *);
void *OPENSSL_sk_value(const OPENSSL_STACK *, int);
void *OPENSSL_sk_shift(OPENSSL_STACK *st);

X509 *PEM_read_bio_X509(BIO *bp, X509 **x, pem_password_cb *cb, void *u);
X509_NAME *X509_get_subject_name(const X509 *x);
X509_NAME *X509_get_issuer_name(const X509 *x);

X509 *X509_new(void);
void X509_free(X509 *a);

int X509_digest(const X509 *data, const EVP_MD *type, unsigned char *md, unsigned int *len);
]])

local C = ffi.C
local openssl_error = base.openssl_error
local ffi_assert = base.ffi_assert
local tocdata = base.tocdata
local assert = assert
local _M = {}
local mt = {
  __index = _M,
  __new = function(ct, x509)
    if x509 == nil then
      return nil, openssl_error()
    else
      return ffi.new(ct, x509)
    end
  end,
  __gc = function(self)
    C.X509_free(self.cdata)
  end
}

local X509 = ffi.metatype('struct { X509 *cdata; }', mt)

local function parse_pem_cert(str)
  local bio = BIO.new()

  assert(bio:write(str))

  return X509(C.PEM_read_bio_X509(bio.cdata, nil, nil, nil))
end

local function normalize_pem_cert(str)
  if not str then return end
  if #(str) == 0 then return end

  -- using also jit compiler (j) will result in a segfault with some certificates
  return re_gsub(str, [[\s(?!CERTIFICATE)]], '\n', 'o')
end

function _M.parse_pem_cert(str)
  local crt = normalize_pem_cert(str)

  if crt then
    return parse_pem_cert(crt)
  else
    return nil, 'invalid certificate'
  end
end

function _M:subject_name()
  -- X509_get_subject_name() returns the subject name of certificate x.
  -- The returned value is an internal pointer which MUST NOT be freed.
  -- https://www.openssl.org/docs/man1.1.0/crypto/X509_get_subject_name.html
  return X509_NAME.new(C.X509_get_subject_name(tocdata(self)))
end

function _M:issuer_name()
  -- X509_get_issuer_name() and X509_set_issuer_name() are identical to X509_get_subject_name()
  -- and X509_set_subject_name() except the get and set the issuer name of x.
  -- https://www.openssl.org/docs/man1.1.0/crypto/X509_get_subject_name.html
  return X509_NAME.new(C.X509_get_issuer_name(tocdata(self)))
end

function _M:digest(name)
  local evp = EVP_MD.new(name) -- TODO: this EVP_MD object can he cached or passed
  local md_size = #evp
  local buf = ffi.new("unsigned char[?]", md_size)
  local len = ffi.new("unsigned int[1]", md_size)

  ffi_assert(C.X509_digest(tocdata(self), tocdata(evp), buf, len), 1)

  return ffi.string(buf, len[0])
end

function _M:hexdigest(evp_md)
  local digest = self:digest(evp_md)

  return resty_str.to_hex(digest)
end

return _M
