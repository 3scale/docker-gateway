local X509 = require('resty.openssl.x509')
local base = require('resty.openssl.base')

local CA = X509.parse_pem_cert([[
-----BEGIN CERTIFICATE-----
MIICvDCCAaQCCQCep4rpEMmCcDANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVD
ZXJ0aWZpY2F0ZSBBdXRob3JpdHkwHhcNMTgxMjA2MTcwNTQ3WhcNMjgxMjAzMTcw
NTQ3WjAgMR4wHAYDVQQDDBVDZXJ0aWZpY2F0ZSBBdXRob3JpdHkwggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCqIfkTccBdVmBqoewL2gBnkDOwk9cKBcLn
uIPge4GfO1Vm4AhDFyZOH9gUmjRH+5Dfu/G+dq7U1jOxTQnvs5U/4857PCTc/rdf
TT/HcG8k6GhBMq6/+gwtT/nOxcFmDkyAOBR2DpvwOd1soOU7lokHkDYTv+kPKrRP
Gc6x7cl3NrsAK154u1xNAGDZiEeThBmi2EanTEZOx4dqkc5pD89P5A/vwjV5LJ+v
jtL+P1FOgK57B3fVFqTL1TNOQdH9BWRZ7z3ZPfSn1PokKA4fazTOZ0iXeQVSIqju
msRk91o+CFXNPJS8NRMsp6Nk6iClyXtaxBWzAcnAxSf9u/UZ6murAgMBAAEwDQYJ
KoZIhvcNAQELBQADggEBAIZo62o53KVLWnDCBxFHwhKVgPa95o1E3RJWuRTI8kdX
L8tehLHorqOCZ1zNIDv8l2QErVUvcxwL/lpuJWZLUvhHPYUg6FDKB+vapVd1yRgR
o4fWkEQkMiKZ4bsSmM00udS5pYGiMHc3vjBcmEPzACIfcv+K29F58Lb3v2ccIXh3
5pQvDYhqaeivRK6JIDY/+1UnaQt65DeNDAfGeAdar6DbFW+gju9avYGINRJP+BGC
Wce2mRmiNUqt37UO1+NXSLa9+4By0j5I1dMqCRFjwQBUaDgrhQf1xpVbEQ30myyy
Ci818xLwDp7CENLKIBNtg88u9Z+ha81pscKiG9WXCLI=
-----END CERTIFICATE-----
]])

local pem = [[
-----BEGIN CERTIFICATE-----
MIICvDCCAaQCCQDyra7VGipAyzANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVD
ZXJ0aWZpY2F0ZSBBdXRob3JpdHkwHhcNMTgxMjA2MTcwOTA1WhcNMjgxMjAzMTcw
OTA1WjAgMQ8wDQYDVQQKDAZDbGllbnQxDTALBgNVBAMMBGN1cmwwggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDt9H6xhm0pGqARRGMaUrSbZvetrN1mo+O4
KuqPRr8I/YhvOEPlc/8VMxF3nyETGjQ+khO9FJGDoDD2S3yGzt1FFiNI6AOPkmux
DZMUQ2alnS7fG0zBUlxRx9otoMx/vH4gnKTfmHofuwPwkLPSWoHf0ZmPLXbm19ds
aKvllOX8vjEjtNprtUzveeDOnuov2GXqo/w+FOnDxYhys1Oidx3LOje5izV7EX4+
+HH+7EwRV7m4+s/G97z5soo1XIZHHQKKC0DONWTOdeLkqLlAqU0nuuRkFzmbrD4u
2haxqcuyficBgbFWZznLDxJ1fMJzen7YbYea1GycTKe6Wt4xviDDAgMBAAEwDQYJ
KoZIhvcNAQELBQADggEBADY5udciqAIAFtJWVQ+AT+5RAWClGlEfi7wAfsGWUIpi
1mQjkGSqbZ4DSEECsRNiokjSyA5Phi9REg8tDCVaovMANncptUX6PJzCkpkdD5Wo
cMWzF8dZpphyZH+RwGM7aTGmdz/mnxKtVoTt++wLNv2jardRKoFvyu+FBzpTbWBe
2EYaIlGHRrIMoU9ZK3D2rGHK3GsakZT3e76/P5KuyIp1+K7IEWmD4Fk3GM6uM+Rc
Q7zGkdX+LBr85p07DHTcDxAwIT6xXh2J1fhiyart5sHkMg6YZ5JpjitIOEypnyiq
KjTINz0a+0rohUDR6BWkdU5R8Bpbw1Pg7Owx9B51KQM=
-----END CERTIFICATE-----
]]

local client = X509.parse_pem_cert([[
-----BEGIN CERTIFICATE-----
MIICvDCCAaQCCQDyra7VGipAyzANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVD
ZXJ0aWZpY2F0ZSBBdXRob3JpdHkwHhcNMTgxMjA2MTcwOTA1WhcNMjgxMjAzMTcw
OTA1WjAgMQ8wDQYDVQQKDAZDbGllbnQxDTALBgNVBAMMBGN1cmwwggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDt9H6xhm0pGqARRGMaUrSbZvetrN1mo+O4
KuqPRr8I/YhvOEPlc/8VMxF3nyETGjQ+khO9FJGDoDD2S3yGzt1FFiNI6AOPkmux
DZMUQ2alnS7fG0zBUlxRx9otoMx/vH4gnKTfmHofuwPwkLPSWoHf0ZmPLXbm19ds
aKvllOX8vjEjtNprtUzveeDOnuov2GXqo/w+FOnDxYhys1Oidx3LOje5izV7EX4+
+HH+7EwRV7m4+s/G97z5soo1XIZHHQKKC0DONWTOdeLkqLlAqU0nuuRkFzmbrD4u
2haxqcuyficBgbFWZznLDxJ1fMJzen7YbYea1GycTKe6Wt4xviDDAgMBAAEwDQYJ
KoZIhvcNAQELBQADggEBADY5udciqAIAFtJWVQ+AT+5RAWClGlEfi7wAfsGWUIpi
1mQjkGSqbZ4DSEECsRNiokjSyA5Phi9REg8tDCVaovMANncptUX6PJzCkpkdD5Wo
cMWzF8dZpphyZH+RwGM7aTGmdz/mnxKtVoTt++wLNv2jardRKoFvyu+FBzpTbWBe
2EYaIlGHRrIMoU9ZK3D2rGHK3GsakZT3e76/P5KuyIp1+K7IEWmD4Fk3GM6uM+Rc
Q7zGkdX+LBr85p07DHTcDxAwIT6xXh2J1fhiyart5sHkMg6YZ5JpjitIOEypnyiq
KjTINz0a+0rohUDR6BWkdU5R8Bpbw1Pg7Owx9B51KQM=
-----END CERTIFICATE-----
]])

local _M = require('resty.openssl.x509.store')

describe('OpenSSL X509 Store', function()
  describe('.new', function()
    it('returns cdata', function ()
      assert.equals('table', type(_M.new()))
      assert.equals('cdata', type(_M.new().store))
    end)
  end)

  describe(':add_cert', function()
    it('has add_cert method', function()
      assert(_M.new().add_cert)
    end)
  end)

  describe(':time', function()
    it('can set and get time', function()
      local store = _M.new()

      assert.equal(0, store:time())

      store:set_time(100)

      assert.equal(100, store:time())
    end)
  end)

  describe(':validate_cert', function()
    after_each(function()
      assert.is_nil(base.openssl_error())
    end)

    it('works with X509 object', function ()
      local x509 = X509.parse_pem_cert(pem)
      local store = _M.new()

      assert.returns_error('unable to get local issuer certificate', store:validate_cert(x509))
    end)

    it('validates missing certificate', function()
      local store = _M.new()

      assert.returns_error('Invalid certificate verification context', store:validate_cert())
    end)

    it('validates self signed certificate', function()
      local store = _M.new()

      assert.returns_error('self signed certificate', store:validate_cert(CA))

      store:add_cert(CA)
      assert(store:validate_cert(CA))
    end)

    it('validates certificate by itself', function()
      local store = _M.new()

      assert.returns_error('unable to get local issuer certificate', store:validate_cert(client))

      store:add_cert(client)
      assert(store:validate_cert(client))
    end)

    it('validates certificate by CA', function()
      local store = _M.new()

      assert.returns_error('unable to get local issuer certificate', store:validate_cert(client))

      store:add_cert(CA)
      assert(store:validate_cert(client))
    end)
  end)
end)
