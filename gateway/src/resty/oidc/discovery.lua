local setmetatable = setmetatable
local type = type
local len = string.len

local resty_url = require 'resty.url'
local http_ng = require "resty.http_ng"
local resty_env = require 'resty.env'
local Mime = require 'resty.mime'
local cjson = require('cjson')
local jwk = require('resty.oidc.jwk')

local oidc_log_level = ngx[string.upper(resty_env.value('APICAST_OIDC_LOG_LEVEL') or 'err')] or ngx.ERR

local _M = { }

local mt = { __index = _M }

local function openid_configuration_url(issuer)
    if issuer and type(issuer) == 'string' and len(issuer) > 0 then
        return resty_url.join(issuer, '.well-known/openid-configuration')
    end
end

local function mime_type(content_type)
    return Mime.new(content_type).media_type
end

local function decode_json(response)
    if mime_type(response.headers.content_type) == 'application/json' then
        return cjson.decode(response.body)
    else
        return nil, 'not json'
    end
end

function _M.new(http_backend)
    local http_client = http_ng.new{
        backend = http_backend,
        options = {
            ssl = { verify = resty_env.enabled('OPENSSL_VERIFY') }
        }
    }

    local self = { http_client = http_client }

    return setmetatable(self, mt)
end

--- Fetch and return OIDC configuration from well known endpoint <issuer>/.well-known/openid-configuration
-- @tparam string issuer URL to the Issuer (without the .well-known/openid-configuration)
function _M:openid_configuration(issuer)
    local http_client = self.http_client

    if not http_client then
        return nil, 'not initialized'
    end

    local uri = openid_configuration_url(issuer)

    if not uri then
        return nil, 'no OIDC endpoint'
    end

    local _, err = resty_url.parse(uri)
    if err then
      ngx.log(ngx.WARN, 'OIDC url is not valid, uri: "' .. uri ..'", error: ' .. err)
      return nil, 'OIDC url is not valid, uri: "' .. uri ..'", error: ' .. err
    end

    local res = http_client.get(uri)

    if res.status ~= 200 then
        ngx.log(oidc_log_level, 'failed to get OIDC Provider from ', uri, ' status: ', res.status, ' body: ', res.body)
        return nil, 'could not get OpenID Connect configuration'
    end

    local config = decode_json(res)

    if not config then
        ngx.log(oidc_log_level, 'invalid OIDC Provider, expected application/json got:  ', res.headers.content_type, ' body: ', res.body)
        return nil, 'invalid JSON'
    end

    return config
end

--- Fetch and convert JWK keys. Each key will get .pem property with PEM formatted key.
-- @tparam table configuration OIDC configuration from :openid_configuration
-- @treturn table list of JWK keys
function _M:jwks(configuration)
    local http_client = self.http_client

    if not http_client then
        return nil, 'not initialized'
    end

    if not configuration then
        return nil, 'no config'
    end

    local jwks_uri = configuration.jwks_uri

    if not jwks_uri or jwks_uri == ngx.null then
        return nil, 'no jwks_uri'
    end

    local res = http_client.get(jwks_uri)

    if res.status == 200 then
        return jwk.convert_keys(decode_json(res))
    else
        return nil, 'invalid response'
    end
end

--- Fetch whole OIDC configuration through OIDC Discovery.
-- @tparam string issuer URL to the Issuer (without the .well-known/openid-configuration)
-- @treturn table
function _M:call(issuer)
    local http_client = self.http_client

    if not http_client then
        return nil, 'not initialized'
    end

    local config, err = _M.openid_configuration(self, issuer)
    if not config then return nil, err end

    return { config = config, issuer = config.issuer, keys = _M.jwks(self, config) }
end

return _M
