# APIcast parameters

APIcast v2 has a number of parameters configured as [environment variables](#environment-variables) that can modify the behavior of the gateway. The following reference provides descriptions of these parameters.

Note that when deploying APIcast v2 with OpenShift, some of these parameters can be configured via OpenShift template parameters. The latter can be consulted directly in the [template](https://raw.githubusercontent.com/3scale/apicast/master/openshift/apicast-template.yml).

## Environment variables

### `APICAST_BACKEND_CACHE_HANDLER`

**Values:** strict | resilient  
**Default:** strict  
**Deprecated:** Use [Caching](../gateway/src/apicast/policy/caching/apicast-policy.json) policy instead.

Defines how the authorization cache behaves when backend is unavailable.
Strict will remove cached application when backend is unavailable.
Resilient will do so only on getting authorization denied from backend.

### `APICAST_CONFIGURATION_CACHE`

**Values:** _a number_  
**Default:** 0

Specifies the period (in seconds) that the configuration will be stored in the cache for. Can take the following values:
- `0`: disables the cache. The configuration will not be not stored. This is not compatible with `boot` mode of `APICAST_CONFIGURATION_LOADER` parameter. When used together with `lazy` value of `APICAST_CONFIGURATION_LOADER`, APIcast will reload the configuration on every request.
- a positive number ( > 0 ): specifies the interval in seconds between configuration reload. For example, when APIcast is started with `APICAST_CONFIGURATION_CACHE=300` and `APICAST_CONFIGURATION_CACHE=boot`, it will load the configuration on boot, and will reload it every 5 minutes (300 seconds).
- a negative number ( < 0 ): disables reloading. The cache entries will never be removed from the cache once stored, and the configuration will never be reloaded.

### `APICAST_CONFIGURATION_LOADER`

**Values:** boot | lazy  
**Default:** lazy

Defines how to load the configuration.
In `boot` mode APIcast will request the configuration to the API manager when the gateway starts.
In `lazy` mode APIcast will load the configuration on demand for each incoming request (to guarantee a complete refresh on each request `APICAST_CONFIGURATION_CACHE` should be set to `0`).

### `APICAST_CUSTOM_CONFIG`

**Deprecated:** Use [policies](./policies.md) instead.

Defines the name of the Lua module that implements custom logic overriding the existing APIcast logic.

### `APICAST_ENVIRONMENT`

**Default:**  
**Value:** string\[:<string>\]  
**Example:** production:cloud-hosted

Double colon (`:`) separated list of environments (or paths) APIcast should load.
It can be used instead of `-e` or `---environment` parameter on the CLI and for example
stored in the container image as default environment. Any value passed on the CLI overrides this variable.

### `APICAST_LOAD_SERVICES_WHEN_NEEDED`
**Values:**
- `true` or `1` for _true_
- `false`, `0` or empty for _false_

**Default:** _false_

This option can be used when there are many services configured. However, its
performance depends on additional factors such as the number of services, the
latency between APIcast and the 3scale Admin Portal, the Time To Live (TTL) of
the configuration, etc.

By default, APIcast loads all the services each time it downloads its
configuration from the Admin Portal. With a large number of services, this could
become problematic. When this option is enabled, the configurations are loaded
lazily. APIcast will only load the ones configured for the host specified in the
host header of the request.

Notes:
- The caching defined by `APICAST_CONFIGURATION_CACHE` applies.
- This option will be disabled when `APICAST_CONFIGURATION_LOADER` is `boot`.
- Not compatible with `APICAST_PATH_ROUTING`.

### `APICAST_LOG_FILE`

**Default:** _stderr_

Defines the file that will store the OpenResty error log. It is used by `bin/apicast` in the `error_log` directive. Refer to [NGINX documentation](http://nginx.org/en/docs/ngx_core_module.html#error_log) for more information. The file path can be either absolute, or relative to the prefix directory (`apicast` by default) 

### `APICAST_LOG_LEVEL`

**Values:** debug | info | notice | warn | error | crit | alert | emerg  
**Default:** warn

Specifies the log level for the OpenResty logs.

### `APICAST_ACCESS_LOG_FILE`

**Default:** _stdout_

Defines the file that will store the access logs.


### `APICAST_OIDC_LOG_LEVEL`

**Values:** debug | info | notice | warn | error | crit | alert | emerg  
**Default:** err

Allows to set the log level for the logs related to OpenID Connect integration


### `APICAST_MANAGEMENT_API`

**Values:**

- `disabled`: completely disabled, just listens on the port
- `status`: enables the `/status/` endpoint for health checks, and the `/policies` endpoint that shows the list of available policies.
- `policies`: enables only the `/policies` endpoint.
- `debug`: full API is open

The [Management API](./management-api.md) is powerful and can control the APIcast configuration.
You should enable the debug level only for debugging.

### `APICAST_MODULE`

**Default:** apicast  
**Deprecated:** Use [policies](./policies.md) instead.

Specifies the name of the main Lua module that implements the API gateway logic. Custom modules can override the functionality of the default `apicast.lua` module. See [an example](../examples/custom-module) of how to use modules.

### `APICAST_OAUTH_TOKENS_TTL`

**Values:** _a number_  
**Default:** 604800

When configured to authenticate using OAuth, this param specifies the TTL (in seconds) of the tokens created.

### `APICAST_PATH_ROUTING`

**Values:**
- `true` or `1` for _true_
- `false`, `0` or empty for _false_

When this parameter is set to _true_, the gateway will use path-based routing in addition to the default host-based routing. The API request will be routed to the first service that has a matching mapping rule, from the list of services for which the value of the `Host` header of the request matches the _Public Base URL_.

### `APICAST_PATH_ROUTING_ONLY`

**Values:**
- `true` or `1` for _true_
- `false`, `0` or empty for _false_

When this parameter is set to _true_, the gateway uses path-based routing and will not fallback to the default host-based routing. The API request will be routed to the first service that has a matching mapping rule, from the list of services for which the value of the `Host` header of the request matches the _Public Base URL_.

This parameter has precedence over `APICAST_PATH_ROUTING`. If `APICAST_PATH_ROUTING_ONLY` is enabled, APIcast will only do path-based routing regardless of the value of `APICAST_PATH_ROUTING`.

### `APICAST_POLICY_LOAD_PATH`

**Default**: `APICAST_DIR/policies`  
**Value:**: string\[:<string>\]  
**Example**: `~/apicast/policies:$PWD/policies`

Double colon (`:`) separated list of paths where APIcast should look for policies.
It can be used to first load policies from a development directory or to load examples.

### `APICAST_PROXY_HTTPS_CERTIFICATE_KEY`

**Default:**  
**Value:** string  
**Example:** /home/apicast/my_certificate.key

The path to the key of the client SSL certificate.

### `APICAST_PROXY_HTTPS_CERTIFICATE`

**Default:**  
**Value:** string  
**Example:** /home/apicast/my_certificate.crt

The path to the client SSL certificate that APIcast will use when connecting
with the upstream. Notice that this certificate will be used for all the
services in the configuration.

### `APICAST_PROXY_HTTPS_PASSWORD_FILE`

**Default:**  
**Value:** string  
**Example:** /home/apicast/passwords.txt

Path to a file with passphrases for the SSL cert keys specified with
`APICAST_PROXY_HTTPS_CERTIFICATE_KEY`.

### `APICAST_PROXY_HTTPS_SESSION_REUSE`

**Default:** on  
**Values:**
- `on`: reuses SSL sessions.
- `off`: does not reuse SSL sessions.

### `APICAST_REPORTING_THREADS`

**Default**: 0  
**Value:** integer >= 0  
**Experimental:** Under extreme load might have unpredictable performance and lose reports.

Value greater than 0 is going to enable out-of-band reporting to backend.
This is a new **experimental** feature for increasing performance. Client
won't see the backend latency and everything will be processed asynchronously.
This value determines how many asynchronous reports can be running simultaneously
before the client is throttled by adding latency.

### `APICAST_RESPONSE_CODES`

**Values:**
- `true` or `1` for _true_
- `false`, `0` or empty for _false_

**Default:** \<empty\> (_false_)

When set to _true_, APIcast will log the response code of the response returned by the API backend in 3scale. In some plans this information can later be consulted from the 3scale admin portal.
Find more information about the Response Codes feature on the [3scale support site](https://access.redhat.com/documentation/en-us/red_hat_3scale/2.saas/html/analytics/response-codes-tracking).

### `APICAST_SERVICES_FILTER_BY_URL`
**Value:** a PCRE (Perl Compatible Regular Expression)
**Example:** .*.example.com

Used to filter the service configured in the 3scale API Manager, the filter
matches with the public base URL. Services that do not match the filter will be
discarded. If the regular expression cannot be compiled no services will be
loaded. 

Note: If a service does not match, but is included in the
`APICAST_SERVICES_LIST`, service will not be discarded

Example:

Regexp Filter: http:\/\/.*.google.com
Service 1: backend endpoint http://www.google.com
Service 2: backend endpoint http://www.yahoo.com
Service 3: backend endpoint http://mail.google.com
Service 4: backend endpoint http://mail.yahoo.com

The services that will be configured in Apicast will be 1 and 3. Services 2 and
4 will be discarded.

### `APICAST_SERVICES_LIST`
**Value:** a comma-separated list of service IDs

Used to filter the services configured in the 3scale API Manager, and only use the configuration for specific services in the gateway, discarding those services' IDs that are not specified in the list.
Service IDs can be found on the **Dashboard > APIs** page, tagged as _ID for API calls_.

### `APICAST_SERVICE_${ID}_CONFIGURATION_VERSION`

Replace `${ID}` with the actual Service ID. The value should be the configuration version you can see in the configuration history on the Admin Portal.

Setting it to a particular version will prevent it from auto-updating and will always use that version.

### `APICAST_UPSTREAM_RETRY_CASES`

**Default**:
**Values**: error | timeout | invalid_header | http_500 | http_502 | http_503 | http_504 | http_403 | http_404 | http_429 | non_idempotent | off

Used only when the retry policy is configured. Specified in which cases a request to the upstream API should be retried.
This accepts the same values as https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_next_upstream

### `APICAST_WORKERS`

**Default:** auto  
**Values:** _number_ | auto

This is the value that will be used in the nginx `worker_processes` [directive](http://nginx.org/en/docs/ngx_core_module.html#worker_processes). By default, APIcast uses `auto`, except for the development environment where `1` is used.

### `BACKEND_ENDPOINT_OVERRIDE`

URI that overrides the backend endpoint. By default, it is the external route. 
This parameter is useful when deploying APIcast into the same OpenShift cluster than 3scale, as when using the internal hostname of the backend listener service instead of the public route. 

**Example**: `http://backend-listener.<3scale-namespace>.svc.cluster.local:3000`

### `OPENSSL_VERIFY`

**Values:**
- `0`, `false`: disable peer verification
- `1`, `true`: enable peer verification

Controls the OpenSSL Peer Verification. It is off by default, because OpenSSL can't use system certificate store.
It requires custom certificate bundle and adding it to trusted certificates.

It is recommended to use https://github.com/openresty/lua-nginx-module#lua_ssl_trusted_certificate and point to to
certificate bundle generated by [export-builtin-trusted-certs](https://github.com/openresty/openresty-devel-utils/blob/master/export-builtin-trusted-certs).

### `REDIS_HOST`

**Default:** `127.0.0.1`

APIcast requires a running Redis instance for OAuth 2.0 Authorization code flow. `REDIS_HOST` parameter is used to set the hostname of the IP of the Redis instance.

### `REDIS_PORT`

**Default:** 6379

APIcast requires a running Redis instance for OAuth 2.0 Authorization code flow. `REDIS_PORT` parameter can be used to set the port of the Redis instance.

### `REDIS_URL`

**Default:** no value

APIcast requires a running Redis instance for OAuth 2.0 Authorization code flow. `REDIS_URL` parameter can be used to set the full URI as DSN format like: `redis://PASSWORD@HOST:PORT/DB`. Takes precedence over `REDIS_PORT` and `REDIS_HOST`.

### `RESOLVER`

Allows to specify a custom DNS resolver that will be used by OpenResty. If the `RESOLVER` parameter is empty, the DNS resolver will be autodiscovered.

### `THREESCALE_CONFIG_FILE`

Path to the JSON file with the configuration for the gateway. The configuration can be downloaded from the 3scale admin portal using the URL: `<schema>://<admin-portal-domain>/admin/api/nginx/spec.json` (**Example**: `https://account-admin.3scale.net/admin/api/nginx/spec.json`).

When the gateway is deployed using Docker, the file has to be injected to the docker image as a read only volume, and the path should indicate where the volume is mounted, i.e. path local to the docker container.

You can find sample configuration files in [examples](https://github.com/3scale/apicast/tree/master/examples/configuration) folder.

It is **required** to provide either `THREESCALE_PORTAL_ENDPOINT` or `THREESCALE_CONFIG_FILE` (takes precedence) for the gateway to run successfully.

### `THREESCALE_DEPLOYMENT_ENV`

**Values:** staging | production  
**Default:** production

The value of this environment variable will be used to define the environment for which the configuration will be downloaded from 3scale (Staging or Production), when using new APIcast.

The value will also be used in the header `X-3scale-User-Agent` in the authorize/report requests made to 3scale Service Management API. It is used by 3scale just for statistics.

### `THREESCALE_PORTAL_ENDPOINT`

URI that includes your password and portal endpoint in the following format: `<schema>://<password>@<admin-portal-domain>`. The `<password>` can be either the provider key or an access token for the 3scale Account Management API. `<admin-portal-domain>` is the URL used to log into the admin portal.

**Example:** `https://access-token@account-admin.3scale.net`.

When `THREESCALE_PORTAL_ENDPOINT` environment variable is provided, the gateway will download the configuration from 3scale on initializing. The configuration includes all the settings provided on the Integration page of the API(s).

It is **required** to provide either `THREESCALE_PORTAL_ENDPOINT` or `THREESCALE_CONFIG_FILE` (takes precedence) for the gateway to run successfully.


### `OPENTRACING_TRACER`

**Example:** `jaeger`

This environment variable controls which tracing library will be loaded, right now, there's only one opentracing tracer available, `jaeger`.

If empty, opentracing support will be disabled.


### `OPENTRACING_CONFIG`

This environment variable is used to determine the config file for the opentracing tracer, if `OPENTRACING_TRACER` is not set, this variable will be ignored.

Each tracer has a default configuration file:
    * `jaeger`: `conf.d/opentracing/jaeger.example.json`

You can choose to mount a different configuration than the provided by default by setting the file path using this variable.

**Example:** `/tmp/jaeger/jaeger.json`

### `OPENTRACING_FORWARD_HEADER`

**Default:** `uber-trace-id`

This environment variable controls the HTTP header used for forwarding opentracing information, this HTTP header will be forwarded to upstream servers.


### `APICAST_HTTPS_PORT`

**Default:** no value

Controls on which port APIcast should start listening for HTTPS connections. If this clashes with HTTP port it will be used only for HTTPS.

### `APICAST_HTTPS_CERTIFICATE`

**Default:** no value

Path to a file with X.509 certificate in the PEM format for HTTPS.

### `APICAST_HTTPS_CERTIFICATE_KEY`

**Default:** no value

Path to a file with the X.509 certificate secret key in the PEM format.

### `APICAST_HTTPS_VERIFY_DEPTH`

**Default:** 1
**Values:** positive integers

Defines the maximum length of the client certificate chain.
If this parameter has 1 as its value, it implies that this length might include one additional certificate (eg. intermediate CA).

### `all_proxy`, `ALL_PROXY`

**Default:** no value
**Value:** string  
**Example:** `http://forward-proxy:80`

Defines a HTTP proxy to be used for connecting to services if a protocol-specific proxy is not specified. Authentication is not supported.

### `http_proxy`, `HTTP_PROXY`

**Default:** no value
**Value:** string  
**Example:** `http://forward-proxy:80`

Defines a HTTP proxy to be used for connecting to HTTP services. Authentication is not supported.

### `https_proxy`, `HTTPS_PROXY`

**Default:** no value
**Value:** string  
**Example:** `http://forward-proxy:80`

Defines a HTTP proxy to be used for connecting to HTTPS services. Authentication is not supported.

### `no_proxy`, `NO_PROXY`

**Default:** no value
**Values:** string\[,<string>\]; `*`  
**Example:** `foo,bar.com,.extra.dot.com`

Defines a comma-separated list of hostnames and domain names for which the requests should not be proxied. Setting to a single `*` character, which matches all hosts, effectively disables the proxy.

### `APICAST_EXTENDED_METRICS`

**Default:** false
**Value:** boolean
**Example:** "true"

Enables additional information on Prometheus metrics; some labels will be used
with specific information that will provide more in-depth details about APIcast.

The metrics that will have extended information are:

- total_response_time_seconds: labels service_id and service_system_name
- upstream_response_time_seconds: labels service_id and service_system_name
- upstream_status: labels service_id and service_system_name
