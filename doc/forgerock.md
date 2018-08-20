# ForgeRock

## Development environment

```shell
docker run --rm -p 8000:8080 forgerock-docker-public.bintray.io/forgerock/openam:6.0.0
```

And open http://localhost:8000/openam/. Accept the license, fill out the admin password (user is amAdmin).


Create a test realm, create OAuth provider OpenID Connect.

Then the OIDC Discovery works:

```shell
curl http://localhost:8000/openam/oauth2/realms/test/.well-known/openid-configuration
```

And returns following JSON:

```json
{
  "request_parameter_supported": true,
  "claims_parameter_supported": false,
  "introspection_endpoint": "http://localhost:8000/openam/oauth2/realms/root/realms/test/introspect",
  "check_session_iframe": "http://localhost:8000/openam/oauth2/realms/root/realms/test/connect/checkSession",
  "scopes_supported": ["address", "phone", "openid", "profile", "email"],
  "issuer": "http://localhost:8000/openam/oauth2/test",
  "id_token_encryption_enc_values_supported": ["A256GCM", "A192GCM", "A128GCM", "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512"],
  "acr_values_supported": [ ],
  "authorization_endpoint": "http://localhost:8000/openam/oauth2/realms/root/realms/test/authorize",
  "request_object_encryption_enc_values_supported": ["A256GCM", "A192GCM", "A128GCM", "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512"],
  "rcs_request_encryption_alg_values_supported": ["RSA-OAEP", "RSA-OAEP-256", "A128KW", "RSA1_5", "A256KW", "dir", "A192KW"],
  "claims_supported": [
    "zoneinfo",
    "address",
    "profile",
    "name",
    "phone_number",
    "given_name",
    "locale",
    "family_name",
    "email"
  ],
  "rcs_request_signing_alg_values_supported": [
    "PS384",
    "ES384",
    "RS384",
    "HS256",
    "HS512",
    "ES256",
    "RS256",
    "HS384",
    "ES512",
    "PS256",
    "PS512",
    "RS512"
  ],
  "token_endpoint_auth_methods_supported": ["client_secret_post", "private_key_jwt", "client_secret_basic"],
  "token_endpoint": "http://localhost:8000/openam/oauth2/realms/root/realms/test/access_token",
  "response_types_supported": [
    "code token id_token",
    "code",
    "code id_token",
    "device_code",
    "id_token",
    "code token",
    "token",
    "token id_token"
  ],
  "request_uri_parameter_supported": true,
  "rcs_response_encryption_enc_values_supported": ["A256GCM", "A192GCM", "A128GCM", "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512"],
  "end_session_endpoint": "http://localhost:8000/openam/oauth2/realms/root/realms/test/connect/endSession",
  "rcs_request_encryption_enc_values_supported": ["A256GCM", "A192GCM", "A128GCM", "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512"],
  "version": "3.0",
  "rcs_response_encryption_alg_values_supported": ["RSA-OAEP", "RSA-OAEP-256", "A128KW", "A256KW", "RSA1_5", "dir", "A192KW"],
  "userinfo_endpoint": "http://localhost:8000/openam/oauth2/realms/root/realms/test/userinfo",
  "id_token_encryption_alg_values_supported": ["RSA-OAEP", "RSA-OAEP-256", "A128KW", "A256KW", "RSA1_5", "dir", "A192KW"],
  "jwks_uri": "http://localhost:8000/openam/oauth2/realms/root/realms/test/connect/jwk_uri",
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": [
    "PS384",
    "ES384",
    "RS384",
    "HS256",
    "HS512",
    "ES256",
    "RS256",
    "HS384",
    "ES512",
    "PS256",
    "PS512",
    "RS512"
  ],
  "registration_endpoint": "http://localhost:8000/openam/oauth2/realms/root/realms/test/register",
  "request_object_signing_alg_values_supported": [
    "PS384",
    "ES384",
    "RS384",
    "HS256",
    "HS512",
    "ES256",
    "RS256",
    "HS384",
    "ES512",
    "PS256",
    "PS512",
    "RS512"
  ],
  "request_object_encryption_alg_values_supported": ["RSA-OAEP", "RSA-OAEP-256", "A128KW", "RSA1_5", "A256KW", "dir", "A192KW"],
  "rcs_response_signing_alg_values_supported": [
    "PS384",
    "ES384",
    "RS384",
    "HS256",
    "HS512",
    "ES256",
    "RS256",
    "HS384",
    "ES512",
    "PS256",
    "PS512",
    "RS512"
  ]
}
```


And the jwk endpoint:


```shell
curl http://localhost:8000/openam/oauth2/realms/root/realms/test/connect/jwk_uri
```

```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "DkKMPE7hFVEn77WWhVuzaoFp4O8=",
      "use": "enc",
      "alg": "RSA-OAEP",
      "n": "i7t6m4d_02dZ8dOe-DFcuUYiOWueHlNkFwdUfOs06eUETOV6Y9WCXu3D71dbF0Fhou69ez5c3HAZrSVS2qC1Htw9NkVlLDeED7qwQQMmSr7RFYNQ6BYekAtn_ScFHpq8Tx4BzhcDb6P0-PHCo-bkQedxwhbMD412KSM2UAVQaZ-TW-ngdaaVEs1Cgl4b8xxZ9ZuApXZfpddNdgvjBeeYQbZnaqU3b0P5YE0s0YvIQqYmTjxh4RyLfkt6s_BS1obWUOC-0ChRWlpWE7QTEVEWJP5yt8hgZ5MecTmBi3yZ_0ts3NsL83413NdbWYh-ChtP696mZbJozflF8jR9pewTbQ",
      "e": "AQAB"
    },
    {
      "kty": "RSA",
      "kid": "4iCKFB0RXIxytor1r3ToBdRievs=",
      "use": "sig",
      "alg": "RS256",
      "n": "i7t6m4d_02dZ8dOe-DFcuUYiOWueHlNkFwdUfOs06eUETOV6Y9WCXu3D71dbF0Fhou69ez5c3HAZrSVS2qC1Htw9NkVlLDeED7qwQQMmSr7RFYNQ6BYekAtn_ScFHpq8Tx4BzhcDb6P0-PHCo-bkQedxwhbMD412KSM2UAVQaZ-TW-ngdaaVEs1Cgl4b8xxZ9ZuApXZfpddNdgvjBeeYQbZnaqU3b0P5YE0s0YvIQqYmTjxh4RyLfkt6s_BS1obWUOC-0ChRWlpWE7QTEVEWJP5yt8hgZ5MecTmBi3yZ_0ts3NsL83413NdbWYh-ChtP696mZbJozflF8jR9pewTbQ",
      "e": "AQAB"
    },
    {
      "kty": "RSA",
      "kid": "DkKMPE7hFVEn77WWhVuzaoFp4O8=",
      "use": "enc",
      "alg": "RSA-OAEP-256",
      "n": "i7t6m4d_02dZ8dOe-DFcuUYiOWueHlNkFwdUfOs06eUETOV6Y9WCXu3D71dbF0Fhou69ez5c3HAZrSVS2qC1Htw9NkVlLDeED7qwQQMmSr7RFYNQ6BYekAtn_ScFHpq8Tx4BzhcDb6P0-PHCo-bkQedxwhbMD412KSM2UAVQaZ-TW-ngdaaVEs1Cgl4b8xxZ9ZuApXZfpddNdgvjBeeYQbZnaqU3b0P5YE0s0YvIQqYmTjxh4RyLfkt6s_BS1obWUOC-0ChRWlpWE7QTEVEWJP5yt8hgZ5MecTmBi3yZ_0ts3NsL83413NdbWYh-ChtP696mZbJozflF8jR9pewTbQ",
      "e": "AQAB"
    },
    {
      "kty": "RSA",
      "kid": "DkKMPE7hFVEn77WWhVuzaoFp4O8=",
      "use": "enc",
      "alg": "RSA1_5",
      "n": "i7t6m4d_02dZ8dOe-DFcuUYiOWueHlNkFwdUfOs06eUETOV6Y9WCXu3D71dbF0Fhou69ez5c3HAZrSVS2qC1Htw9NkVlLDeED7qwQQMmSr7RFYNQ6BYekAtn_ScFHpq8Tx4BzhcDb6P0-PHCo-bkQedxwhbMD412KSM2UAVQaZ-TW-ngdaaVEs1Cgl4b8xxZ9ZuApXZfpddNdgvjBeeYQbZnaqU3b0P5YE0s0YvIQqYmTjxh4RyLfkt6s_BS1obWUOC-0ChRWlpWE7QTEVEWJP5yt8hgZ5MecTmBi3yZ_0ts3NsL83413NdbWYh-ChtP696mZbJozflF8jR9pewTbQ",
      "e": "AQAB"
    },
    {
      "kty": "EC",
      "kid": "pZSfpEq8tQPeiIe3fnnaWnnr/Zc=",
      "use": "sig",
      "alg": "ES512",
      "x": "AHdVKbNDHym-MiUh6caaod_ktp8PXN6g1zIKLzlaCSOZP82KKaQsfwltAKnMrw129nVx-2kt8x1J1pp1ADe9HtXt",
      "y": "AUqhRKcYvA6lElI3UrfqvpuhVsyEFBQ4cM_E9v4WGnRc_priiTVa_UC7YfCtQJT9F8Oc21v_i57Sp3Mq_vw5ueRd",
      "crv": "P-521"
    },
    {
      "kty": "EC",
      "kid": "I4x/IijvdDsUZMghwNq2gC/7pYQ=",
      "use": "sig",
      "alg": "ES384",
      "x": "k5wSvW_6JhOuCj-9PdDWdEA4oH90RSmC2GTliiUHAhXj6rmTdE2S-_zGmMFxufuV",
      "y": "XfbR-tRoVcZMCoUrkKtuZUIyfCgAy8b0FWnPZqevwpdoTzGQBOXSNi6uItN_o4tH",
      "crv": "P-384"
    },
    {
      "kty": "EC",
      "kid": "Fol7IpdKeLZmzKtCEgi1LDhSIzM=",
      "use": "sig",
      "alg": "ES256",
      "x": "N7MtObVf92FJTwYvY2ZvTVT3rgZp7a7XDtzT_9Rw7IA",
      "y": "uxNmyoocPopYh4k1FCc41yuJZVohxlhMo3KTIJVTP3c",
      "crv": "P-256"
    }
  ]
}
```

OIDC does not use JWT by default, so it has to be enabled in Services > OAuth2 Provider > Use Stateless Access & Refresh Tokens.
Then it needs to be configured to use public key cryptography instead of shared secret by selecting any
RS cypher as "OAuth2 Token Signing Algorithm" in the Advanced tab
(need to save the previous page before changing the tab).

Create an Application to generate Access Token in Applications > OAuth 2.0 > Add Client.
Fill all the fields with some bogus values (even the scope and default scope).

Recommended way of getting the Access Token is using Insomnia - cross platform HTTP client.
Use the "token_endpoint" and "authorization_endpoint" values from the OIDC Discovery endpoint as Authorization and Access Token URL.

In case you get 401 when creating the token terminate Forgerock docker and start again.

After getting JWT Insomnia can make authenticated requests to APIcast. But APIcast needs the Forgerock public key,
so it can verify JWT signature. The JWK endpoint from OIDC Discovery provides JWK encoded certificates.

Use the one with alg RS256 and convert it to normal RSA certificate:
Before it can be configured in the policy it needs to be formatted to the one line format like Keycloak uses.


APIcast does OIDC Discovery only when downloading configuration from System. Passing configuration file from filesystem won't trigger that process.
It is possible to mock System API by static files and a simple webserver:

```shell
gem install adsf
cd examples/configuration/oidc/
adsf
```

And edit `examples/configuration/oidc/admin/api/services/oidc/proxy/configs/production/latest.json` to provide the correct public key.


