# APICast Policy caching

This policy allows to enable and disable caching based on customized conditions. These
conditions can only be applied on the client request, where upstream responses
cannot be used in this policy.

This policy will respect all Cache-Control headers, if the endpoint send a
different timeout, no-cache, etc. this policy will keep the upstream response.

## Example configuration

```
{
  "name": "apicast.policy.content_caching",
  "version": "builtin",
  "configuration": {
    "rules": [
      {
        "cache": true,
        "header": "X-Cache-Status-POLICY",
        "condition": {
          "combine_op": "and",
          "operations": [
            {
              "left": "{{method}}",
              "left_type": "liquid",
              "op": "==",
              "right": "GET"
            }
          ]
        }
      }
    ]
  }
}
```

## Recommended configuration

- Set `APICast Policy caching` as disabled, for any of the following methods: POST, PUT, DELETE.
- If one rule matches, and it enables the cache, the execution will be
  stopped and it will be not disabled. Sort by priority is important here.

## Upstream response headers

At the moment, the NGINX [`proxy_cache_valid`
directive](http://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cache_valid)
information can only be set globally, with the `APICAST_CACHE_STATUS_CODES` and
`APICAST_CACHE_MAX_TIME`. If your upstream requires a different behavior
regarding timeouts, the [`Cache-control`
header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control)
can be used and users can take advantage of that.
