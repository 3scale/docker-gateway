local _M = require('resty.openssl.x509')

local pem = [[
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
]]

local certificate = _M.parse_pem_cert(pem)

describe('OpenSSL X509', function ()

  describe('parse_pem_cert', function ()
    it('returns', function ()
      local crt = _M.parse_pem_cert(pem)

      assert(crt)
    end)

    it('does not crash on invalid certificate', function()
      assert.returns_error('no start line', _M.parse_pem_cert('garbage'))
      assert.returns_error('short header', _M.parse_pem_cert('-----BEGIN CERTIFICATE-----'))
      assert.returns_error('invalid certificate', _M.parse_pem_cert(''))
    end)

    it('parses wrongly formatted newlines', function ()
      assert(_M.parse_pem_cert([[-----BEGIN CERTIFICATE----- MIICvDCCAaQCCQDyra7VGipAyzANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVD ZXJ0aWZpY2F0ZSBBdXRob3JpdHkwHhcNMTgxMjA2MTcwOTA1WhcNMjgxMjAzMTcw OTA1WjAgMQ8wDQYDVQQKDAZDbGllbnQxDTALBgNVBAMMBGN1cmwwggEiMA0GCSqG SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDt9H6xhm0pGqARRGMaUrSbZvetrN1mo+O4 KuqPRr8I/YhvOEPlc/8VMxF3nyETGjQ+khO9FJGDoDD2S3yGzt1FFiNI6AOPkmux DZMUQ2alnS7fG0zBUlxRx9otoMx/vH4gnKTfmHofuwPwkLPSWoHf0ZmPLXbm19ds aKvllOX8vjEjtNprtUzveeDOnuov2GXqo/w+FOnDxYhys1Oidx3LOje5izV7EX4+ +HH+7EwRV7m4+s/G97z5soo1XIZHHQKKC0DONWTOdeLkqLlAqU0nuuRkFzmbrD4u 2haxqcuyficBgbFWZznLDxJ1fMJzen7YbYea1GycTKe6Wt4xviDDAgMBAAEwDQYJ KoZIhvcNAQELBQADggEBADY5udciqAIAFtJWVQ+AT+5RAWClGlEfi7wAfsGWUIpi 1mQjkGSqbZ4DSEECsRNiokjSyA5Phi9REg8tDCVaovMANncptUX6PJzCkpkdD5Wo cMWzF8dZpphyZH+RwGM7aTGmdz/mnxKtVoTt++wLNv2jardRKoFvyu+FBzpTbWBe 2EYaIlGHRrIMoU9ZK3D2rGHK3GsakZT3e76/P5KuyIp1+K7IEWmD4Fk3GM6uM+Rc Q7zGkdX+LBr85p07DHTcDxAwIT6xXh2J1fhiyart5sHkMg6YZ5JpjitIOEypnyiq KjTINz0a+0rohUDR6BWkdU5R8Bpbw1Pg7Owx9B51KQM= -----END CERTIFICATE-----]]))
    end)
  end)

  describe(':name()', function()
    it('returns subject name', function()
      assert.equal('CN = Certificate Authority', tostring(certificate:subject_name()))
    end)

    it('returns issuer name', function()
      assert.equal('CN = Certificate Authority', tostring(certificate:issuer_name()))
    end)
  end)

  describe(':digest', function ()
    it('returns a digest', function ()
      assert(certificate:digest('SHA256'))
    end)
  end)

  describe(':hexdigest', function ()
    it('returns a hex formatted digest', function ()
      assert.equal('874fd0756c3c36c78319ca6e484e670780b86146', certificate:hexdigest('SHA1'))
    end)
  end)
end)
