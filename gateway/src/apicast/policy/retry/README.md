# Retry policy

- [**Description**](#description)
- [**Usage**](#usage)

## Description

This policy allows to retry requests to the upstream API.

## Usage

The configuration of the policy is very simple. It just allows to configure the
number of retries. The policy is configured per service, so users can choose to
enable retries only on some of their services. Also, it is possible to
configure a different number of retries for different services.

Currently, it is not possible to configure in which cases to retry from the
policy. That's controlled with an environment variable that applies to all the
services: `APICAST_UPSTREAM_RETRY_CASES`.

That env variable is used only when the retry policy is enabled and specifies
in which cases the request should should be retried. The env accepts the same
values as the [proxy_next_upstream NGINX directive](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_next_upstream).
So with `APICAST_UPSTREAM_RETRY_CASES = http_503 http_504`, the request is
retried when the upstream returns a 503 or a 504. By default, the env is set to
'error timeout', which is the same default that NGINX applies.
