# Rate Limit policy

- [**Description**](#description)
- [**Types of limits**](#types-of-limits)
- [**Limit definition**](#limit-definition)
- [**Liquid templating**](#liquid-templating)
- [**Requests over limits**](#requests-over-limits)
- [**Per-gateway vs shared**](#per-gateway-vs-shared)
- [**Complete config example**](#complete-config-example)


## Description

The purpose of this policy is to control the rate of traffic sent to the
upstream API. There are several kinds of limits that can be defined. Here are
some examples:

- The client with address 127.0.0.1 can access the specific endpoint
`/something` up to 100 times per minute.
- Requests that contain a JSON web token (JWT) whose `sub` claim has the value
`abc` can make up to 10 calls to the API per second.


## Types of limits

The types of limits supported by the policy are the ones provided by the
[lua-resty-limit-traffic](https://github.com/openresty/lua-resty-limit-traffic)
library:

- leaky_bucket_limiters: based on the "leaky_bucket" algorithm, which is based
on an average number of requests plus a maximum burst size.
- fixed_window_limiters: based on a fixed window of time (last X seconds).
- connection_limiters: based on the concurrent number of connections.

Any limit can be scoped by service or globally.


## Limit definition

The limits have a key that encodes the entities that we want to use to define
the limit (an IP, a service, an endpoint, an ID, the value for a specific
header, etc.). Each limit also has some parameters that vary depending on the
type:

- leaky_bucket_limiters: `rate`, `burst`. Can make up to `rate` requests per
second. It allows exceeding that number by `burst` requests per second,
although an artificial delay is introduced for those requests between `rate`
and `burst` to avoid going over the limits.
- fixed_window_limiters: `count`, `window`. Can make up to `count` requests per
`window` seconds.
- connection_limiters: `conn`, `burst`, `delay`. `conn` is the max number of
concurrent connections allowed. It allows exceeding that number by `burst`
connections per second. `delay` is the number of seconds to delay the
connections that exceed the limit.

Here are some examples:

- Allow 10 requests per minute to `service_A`:

```json
{
  "key": { "name": "service_A" },
  "count": 10,
  "window": 60
}
```

- Allow 100 connections with bursts of 10 with a delay of 1s:

```json
{
  "key": { "name": "service_A" },
  "conn": 100,
  "burst": 10,
  "delay": 1
}
```

There can be several limits defined for each service. When several of them
apply, going over the limits for one of them is enough to reject the request or
delay it.


## Liquid templating

In order to specify more useful limits, we need to be able to define dynamic
keys. The policy supports that by allowing to interpret keys using Liquid.
For example, we can define `{{ remote_addr }}` to limit by the client IP or
`{{ jwt.sub }}` to limit by the `sub` claim of a jwt. When defining keys using
Liquid, we need to specify it using the `name_type` field:

```json
{
  "key": { "name": "{{ jwt.sub }}", "name_type": "liquid" },
  "count": 10,
  "window": 60
}
```

These are the variables supported in liquid:
* uri
* host
* remote_addr
* headers['Some-Header']

The updated list of variables can be found [here](../ngx_variable.lua). Apart
from those, the context shared among policies is also available. The update list
of filters supported can be found [here](../../template_string.lua).


## Requests over limits

The policy can be configured to reject requests that go over limits or just
left the requests go through and log the limit violation instead of rejecting
the request. This is configured with the `error_handling` attribute of the
policy config. It has 2 possible values: `exit` (denies the request) and
`log` (only outputs logs).


## Per-gateway vs shared

By default, limits are applied per-gateway. This means that when you deploy,
for example, 2 APIcasts to have HA, and define a limit like:

```json
{
  "key": { "name": "service_A" },
  "count": 10,
  "window": 60
}
```

It will be possible to make 10 requests in a minute on each of the APIcasts
deployed.

In order to define shared limits, that is, make those 10 requests in total
regardless of the number of APIcasts deployed, the policy provides the option
of using a shared storage. For now, it only supports Redis.

To use Redis, we just need to provide the `redis_url` attribute in the config
of the policy: `"redis_url": "redis://a_host:6379"`


## Complete config examples

```json
{
  "name": "rate_limit",
  "version": "builtin",
  "configuration": {
    "leaky_bucket_limiters": [
      {
        "key": {
          "name": "service_A"
        },
        "rate": 20,
        "burst": 10
      }
    ],
    "connection_limiters": [
      {
        "key": {
          "name": "service_B"
        },
        "conn": 20,
        "burst": 10,
        "delay": 0.5
      }
    ],
    "fixed_window_limiters": [
      {
        "key": {
          "name": "service_C"
        },
        "count": 20,
        "window": 10
      }
    ],
    "redis_url": "redis://localhost:6379"
  }
}
```

Another example with different applications, paths, and limits:
- 2 app IDs: `app_id_1`, `app_id_2`. Assuming they come in the `app-id` header.
- 2 different endpoints: `/path1`, `/path2`.
- Rate_limits:
    - `app_id_1`. 10 rps on `/path1`.
    - `app_id_2`. 20 rps on `/path2`.

```json
{
  "name": "rate_limit",
  "version": "builtin",
  "configuration": {
    "fixed_window_limiters": [
      {
        "key": {
          "name": "app_id_1_path_1"
        },
        "scope": "service",
        "condition": {
          "operations": [
            {
              "left": "{{ uri }}",
              "left_type": "liquid",
              "op": "==",
              "right": "/path1",
              "right_type": "plain"
            },
            {
              "left": "{{ headers['app-id'] }}",
              "left_type": "liquid",
              "op": "==",
              "right": "app_id_1",
              "right_type": "plain"
            }
          ],
          "combine_op": "and"
        },
        "count": 10,
        "window": 1
      },
      {
        "key": {
          "name": "app_id_2_path_2"
        },
        "scope": "service",
        "condition": {
          "operations": [
            {
              "left": "{{ uri }}",
              "left_type": "liquid",
              "op": "==",
              "right": "/path2",
              "right_type": "plain"
            },
            {
              "left": "{{ headers['app-id'] }}",
              "left_type": "liquid",
              "op": "==",
              "right": "app_id_2",
              "right_type": "plain"
            }
          ],
          "combine_op": "and"
        },
        "count": 20,
        "window": 1
      }
    ]
  }
}
```

To know more about the details of what is exactly supported please check the
[policy config schema](apicast-policy.json).
