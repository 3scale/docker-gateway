-- This is a tls description.

local policy = require('apicast.policy')
local _M = policy.new('tls', "builtin")
local tab_new = require('table.new')
local ssl = require('ngx.ssl')
local cjson = require('cjson')
local data_url = require('resty.data_url')

local insert = table.insert
local io_open = io.open
local io_type = io.type
local pack = table.pack
local ipairs = ipairs
local setmetatable = setmetatable

local null = ngx.null
local empty = {}
local new = _M.new

--- Create a Struct like Class, that extract required properties from a table or returns and error.
local function Config(...)
  local properties = pack(...)
  local m = { }
  local mt  = { __index = m }

  function m.new(config)
    if not config and properties then return nil, 'missing table' end

    local self = { }

    for _,property in ipairs(properties) do
      if config[property] ~= null then
        self[property] = config[property]
      end

      if self[property] == nil then
        return nil, 'missing property'
      end
    end

    return setmetatable(self, mt)
  end

  return m
end

local EmbeddedCertificates = Config('certificate', 'certificate_key')
local LocalFilesystemCertificates = Config('certificate_path', 'certificate_key_path')

local function open_file(path)
  local handle, err

  if io_type(path) == 'handle' then
    handle = path
  else
    handle, err = io_open(path)
  end

  return handle, err
end

local function read_file(path)
  local handle, err = open_file(path)

  if err or not handle then
    return nil, err
  end

  handle:seek("set")
  local output = handle:read("*a")
  handle:close()

  return output
end


local function parse_certificates(self, certificate, private_key)
  local err
  self.certificate, err = ssl.parse_pem_cert(certificate)
  if err then return nil, err end

  self.certificate_key, err = ssl.parse_pem_priv_key(private_key)
  if err then return nil, err end

  return true
end

local function parse_data_url(url)
  local uri, err = data_url.parse(url)

  if err then return nil, err end

  return uri.data
end

function EmbeddedCertificates:parse()
  local certificate, certificate_key, err

  certificate, err = parse_data_url(self.certificate)
  if err then return nil, err end


  certificate_key, err = parse_data_url(self.certificate_key)
  if err then return nil, err end

  return parse_certificates(self, certificate, certificate_key)
end

function LocalFilesystemCertificates:parse()
  local certificate, certificate_key, err

  certificate, err = read_file(self.certificate_path)
  if err then return nil, err end

  certificate_key, err = read_file(self.certificate_key_path)
  if err then return nil, err end

  return parse_certificates(self, certificate, certificate_key)
end

local Configurations = { EmbeddedCertificates, LocalFilesystemCertificates }

local function parse_config(table)
  for _, class in ipairs(Configurations) do
    local config, _ = class.new(table)

    if config and config:parse() then
      return config
    end
  end

  return nil, 'configuration does not match any supported type'
end

local function parse_config_certificates(configs)
  local certificates = tab_new(#configs, 0)

  for _, config in ipairs(configs)do
    local cert, err = parse_config(config)
    if err then
      ngx.log(ngx.WARN, 'could not parse certificate ', cjson.encode(config))
    else
      insert(certificates, cert)
    end
  end

  return certificates
end

--- Initialize a TLS policy
-- @tparam[opt] table config Policy configuration.
function _M.new(config)
  local self = new(config)
  self.certificates = parse_config_certificates(config and config.certificates or empty)
  if #self.certificates == 0 then
    ngx.log(ngx.WARN, "No valid certificates loaded")
  end
  return self
end

-- Set the given certificate to be the default one for the request.
-- @tparam cert: certificate table with certificates in der format
local function set_certificate(cert)
  local ok, err = ssl.set_cert(cert.certificate)
  if not ok then
    ngx.log(ngx.ERR, "failed to set certificate: ", err)
    return false
  end

  ok, err = ssl.set_priv_key(cert.certificate_key)
  if not ok then
    ngx.log(ngx.ERR, "failed to set DER private key: ", err)
    return false
  end
  return true
end

function _M:ssl_certificate()
  if #self.certificates == 0 then
    -- No valid certificates in place, continue.
    return
  end

  local ok, err = ssl.clear_certs()
  if not ok then
      ngx.log(ngx.ERR, "failed to clear existing (fallback) certificates, err: ", err)
      return ngx.exit(ngx.ERROR)
  end

  for _, cert in ipairs(self.certificates) do
    if set_certificate(cert) then
      -- Certificate is set correctly, use this one and end the loop.
      ngx.exit(ngx.OK)
      break
    end
  end
end

return _M
