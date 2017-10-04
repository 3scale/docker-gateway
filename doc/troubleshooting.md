# Troubleshooting APIcast

## Generic Troubleshooting

### X-3scale-debug header 

When making an API request you can add some additional headers to the response for troubleshooting purposes by adding the `X-3scale-Debug` header to the request. 

e.g 

`curl -v -H 'X-3scale-Debug: SERVICE_TOKEN' -X GET "https://api.example.com/ping?user_key=1234567"`

This will return the following additional headers:
- `X-3scale-matched-rules`: Any matched methods/metrics in the request e.g `/ping`
- `X-3scale-credentials`: The credentials extracted by APIcast for the request e.g `user_key=1234567`
- `X-3scale-usage`: The usage registered for the methods/metrics in the request e.g `usage[hits]=1`
- `X-3scale-hostname`: The APIcast instance hostname e.g ``

## Self-Managed

### Logging

When running APIcast, the default log level is `warn.` 

You can increase verbosity in the logs by appending (multiple) `-v` parameters when running the apicast binary, e.g 

`THREESCALE_CONFIG_FILE=config.json bin/apicast -v -v -v`

In the above example, the log level would be increased to `debug`, the maximum log level.

You can also decrease verbosity by appending (multiple) `-q` parameters instead, e.g 

`THREESCALE_CONFIG_FILE=config.json bin/apicast -q -q`

this would decrease the log level to `crit`.

### DNS Issues

If you see the following error in your logs `[error] 1619#0: recv() failed (61: Connection refused) while resolving, resolver: 127.0.0.1:53`

It means that APIcast is unable to correctly detect your dns settings, from /etc/resolv.conf. In this case you should copy the nameserver IP 

e.g 

```
.
.
.
nameserver 1.2.3.4
nameserver 5.6.7.8
```

into apicast/http.d/resolver.conf as follows

```
resolver 1.2.3.4 ipv6=off;
```

You can read more about the resolver directive in the [Nginx Documentation](https://nginx.org/en/docs/http/ngx_http_core_module.html#resolver)

### `PATH` Issues

If APIcast doesn't seem to be able to start and returns without any output, check that you have added the openresty binaries to your `PATH` e.g `export PATH=/usr/local/openresty/bin:/usr/local/openresty/nginx/sbin:$PATH`

## Openshift

### Insecure Registry

## Docker

### Logging

When running APIcast, you can increase the default log level (warn) by setting the APICAST_LOG_LEVEL parameter. 

Values: debug | info | notice | warn | error | crit | alert | emerg
