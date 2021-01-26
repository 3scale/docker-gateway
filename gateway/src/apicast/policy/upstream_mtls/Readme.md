# Upstream Mutual TLS policy

This policy enables the Mutual TLS policy per API, so connection to the upstream
API will use the certificates defined in this policy.

## Configuration

### Path configuration

Using certificates Path, both for Openshift and Kubernetes secrets.

```
{
  "name": "apicast.policy.upstream_mtls",
  "configuration": {
      "certificate": "/secrets/client.cer",
      "certificate_type": "path",
      "certificate_key": "/secrets/client.key",
      "certificate_key_type": "path"
  }
}
```

### Embedded configuration

When using http forms and file upload

```
{
  "name": "apicast.policy.upstream_mtls",
  "configuration": {
    "certificate_type": "embedded",
    "certificate_key_type": "embedded",
    "certificate": "data:application/pkix-cert;name=client.cer;base64,XXXXXXXXXxx",
    "certificate_key": "data:application/x-iwork-keynote-sffkey;name=client.key;base64,XXXXXXXX"
  }
}
```

## Additional considerations

This policy overwrites `APICAST_PROXY_HTTPS_CERTIFICATE_KEY` and
`APICAST_PROXY_HTTPS_CERTIFICATE` values and it uses the certificates set by
the policy, so those environment variables will have no effect.
