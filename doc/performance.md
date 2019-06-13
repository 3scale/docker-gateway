# Performance

- [**General guidelines**](#general-guidelines)
- [**Default caching**](#default-caching)
- [**Async reporting threads**](#async-reporting-threads)
- [**Batching policy**](#batching-policy)

This document provides general guidelines to debug performance issues in
APIcast. It also introduces the available caching modes and explains how they
can help in increasing performance.

## General guidelines

When experiencing performance issues in APIcast, the first thing that we
recommend is to identify the component that is responsible for those issues. In
a typical APIcast deployment, there are three components to consider:

- APIcast
- The 3scale backend that authorizes requests and keeps track of the usage
- The upstream API

To measure the latency that APIcast plus the 3scale backend introduce, the first
thing that we need to do is to measure the latency of the upstream API. The next
step consists of using the same tool to run the same benchmark, but this time,
pointing to APIcast instead of pointing to the upstream API directly. Comparing
those results will give us an idea of the latency introduced by APIcast and the
3scale backend.

If you see that the latency introduced by APIcast and the 3scale backend is too
high, and you are using a self-managed APIcast that authorizes against the
3scale backend SaaS, the first thing you can do is to make a simple request to
the 3scale backend from the same machine where APIcast is deployed and measure
the latency.

Backend exposes an endpoint that returns the version:
https://su1.3scale.net/status. An authorization call requires more work because
it needs to verify some keys, limits, and enqueue background jobs. The 3scale
backend is very fast, on average, it does that in a matter of a few
milliseconds, but still, it requires more work than checking the version like
the `/status` endpoint does. So, if a request to `/status` takes -as an example-
around 300 ms from your APIcast environment, an authorization is going to take a
bit more than that for every request that is not cached.


## Default caching

For requests that are not cached, these are the events:

1. APIcast extracts the usage metrics from matching mapping rules
2. APIcast sends those metrics plus the application credentials to the 3scale
backend.
3. The 3scale backend makes the following tasks:
    1. Checks the application keys, and that the reported usage of metrics is
    within the defined limits.
    2. Enqueues a background job to increase the usage of the metrics reported.
    3. Responds to APIcast whether the request should be authorized or not.
4. If the request is authorized, it goes to the upstream.

Note that in this case, the request does not arrive to the upstream until the
3scale backend responds.

With the caching mechanism that comes enabled by default:
- APIcast stores in a cache the result of the authorization call to the 3scale
backend if it was authorized.
- The next request with the same credentials and metrics will use that cached
authorization instead of going to the 3scale backend.
- If the request was not authorized or it is the first time that APIcast
receives those credentials, APIcast will call backend synchronously as explained
above.

When the auth is cached, APIcast first calls the upstream and then, in a phase
called "post action", it calls the 3scale backend and stores the authorization
in the cache to have it ready for the next request. Notice that in this case,
the call to the 3scale backend does not introduce any latency because it does
not happen in request time. There is an important aspect to take into account
though, requests sent in the same connection will need to wait until the "post
action" phase finishes.

Imagine a scenario where a client is using keep-alive and sends a request every
second. If the upstream response time is 100ms and the latency to the 3scale
backend is 500ms, the client will get the response every time in 100ms. The
total of upstream response + reporting would take 600ms. That gives extra 400ms
before the next request comes.

The diagram below illustrates the default caching behavior explained.

```
                                                                ┌────────────────┐
                                                                │    APIcast     │
                              ┌─────────────────────────────────┴────────────────┴───────────────────────────────────┐
                              │                                                                                      │
                              │                                                                                      │
   ┌───────────────────────┐  │                                                                                      │
   │TCP connection (client)│  │                                                                                      │
┌──┴───────────────────────┴──┤                                                                                      │
│                             │                                                                                      │
│                             │                                                                                      │
│                             │   ┌──────────┐                                                                       │
│                             │   │  3scale  │                                                                       │
│         ┌──────────────┐    │ **│   500ms  │**                                                                     │
│         │ HTTP request │    │ * └──────────┘ *  ┌──────────┐                                                       │
│─────────┴──────────────┴────┼─*──────────────*─▶│          │                                                       │
│         ┌──────────────┐    │                   │ Upstream │                                                       │
│   600ms │HTTP response │    │                   │   100ms  │                                                       │
│◀────────┴──────────────┴────┼───────────────────│          │                                                       │
│         ┌──────────────┐    │                   └──────────┘                                                       │
│   600ms │ HTTP request │    │                               ┌──────────┐                                           │
│─────────┴──────────────┴────┼──────────────────────────────▶│          │    post_action                            │
│◀────────┬──────────────┬────┼───────────────────────────────│ Upstream │   ┌───────────┐                           │
│   700ms │HTTP response │    │                               │   100ms  │   │  3scale   │                           │
│         └──────────────┘    │                               │          │─ ▷│   500ms   │                           │
│         ┌──────────────┐    │                               └──────────┘   └───────────┘                           │
│   1200ms│ HTTP request │    │                                                          ┌──────────┐                │
│─────────┴──────────────┴────┼─────────────────────────────────────────────────────────▶│          │   post_action  │
│◀────────┬──────────────┬────┼──────────────────────────────────────────────────────────│ Upstream │  ┌───────────┐ │
│   1300ms│HTTP response │    │                                                          │   100ms  │  │  3scale   │ │
│         └──────────────┘    │                                                          │          ├ ▷│   500ms   │ │
└─────────────────────────────┤                                                          └──────────┘  └───────────┘ │
                              │                                                                                      │
                              └──────────────────────────────────────────────────────────────────────────────────────┘
```

The behavior of the caching mechanism can be changed using the [caching
policy](../gateway/src/apicast/policy/caching).


## Async reporting threads

APIcast has a feature to enable a pool of threads that authorize against
backend. This can improve performance in certain cases.

With this feature enabled, APIcast will first synchronously call 3scale backend
to verify the application and metrics matched by mapping rules. Just like it
does using the caching mechanism enabled by default. The difference is that
subsequent calls to 3scale backend will be reported fully asynchronously as long
as there are free reporting threads in the pool. Reporting threads are global
for the whole gateway and shared between all the services. When a second TCP
connection is made, it will also be fully asynchronous as long as the
authorization is already cached. When there are no free reporting threads, this
mode falls back to the standard async mode and does the reporting in the post
action phase.

This feature can be enabled using the `APICAST_REPORTING_THREADS` environment
variable. Please check
[this](https://github.com/3scale/APIcast/blob/master/doc/parameters.md#apicast_reporting_threads)
for more details.

The diagram below illustrates how the async reporting thread pool works.

```
                                                                              ┌────────────────┐
                                                                              │    APIcast     │
                              ┌───────────────────────────────────────────────┴────────────────┴────────────────────────────────────────────────────┐
                              │                                                               ┌───┬────────────────────┬───┐                        │
                              │                                                               │   │2 reporting threads │   │                        │
┌─────────────────────────────┤                                                               │   └────────────────────┘   │                        │
│   TCP connection (client)   │                                                               │  ┌──────────┐              │                        │
├─────────────────────────────┤                                                               │  │  3scale  │              │                        ├───┐
│                             │                                                      ┌ ─ ─ ─ ─│─▷│   500ms  │              │                        │   │
│                             │                                                               │  └──────────┘              │                        │   │
│                             │   ┌──────────┐                                       │        │  ┌──────────┐ ┌──────────┐ │                        │   │
│                             │   │  3scale  │                                                │  │  3scale  │ │  3scale  │ │                        │   │
│         ┌──────────────┐    │ **│   500ms  │**                                     │     ┌ ─│─▷│   500ms  │ │   500ms  │◁┼ ─ ┐                    │   │
│         │ HTTP request │    │ * └──────────┘ *  ┌──────────┐                                │  └──────────┘ └──────────┘ │                        │   │
│─────────┴──────────────┴────┼─*──────────────*─▶│          │                       │     │  └────────────────────────────┘   │                    │   │
│         ┌──────────────┐    │                   │ Upstream │                                                                                      │   │
│   600ms │HTTP response │    │                   │   100ms  │                       │     │                                   │                    │   │
│◀────────┴──────────────┴────┼───────────────────│          │                                                                                      │   │
│         ┌──────────────┐    │                   └──────────┘                       │     │                                   │                    │   │
│   600ms │ HTTP request │    │                               ┌──────────┐       async                                                              │   │
│─────────┴──────────────┴────┼──────────────────────────────▶│          │     2 threads   │                                   │                    │   │
│◀────────┬──────────────┬────┼───────────────────────────────│ Upstream │     available                                                            │   │
│   700ms │HTTP response │    │                               │   100ms  │           │     │                                   │                    │   │
│         └──────────────┘    │                               │          │─ ─ ─ ─ ─ ─                                                               │   │
│         ┌──────────────┐    │                               └──────────┘                 │                                   │                    │   │
│    700ms│ HTTP request │    │                                           ┌──────────┐    async                                                     │   │
│─────────┴──────────────┴────┼──────────────────────────────────────────▶│          │  1 thread                               │                    │   │
│◀────────┬──────────────┬────┼───────────────────────────────────────────│ Upstream │  available                                                   │   │
│    800ms│HTTP response │    │                                           │   100ms  │     │                                   │                    │   │
│         └──────────────┘    │                                           │          │─ ─ ─                                                         │   │
│         ┌──────────────┐    │                                           └──────────┘                                         │                    │   │
│    800ms│ HTTP request │    │                                                       ┌──────────┐       post_action                                │   │
│─────────┴──────────────┴────┼──────────────────────────────────────────────────────▶│          │ (no threads available)      │                    │   │
│◀────────┬──────────────┬────┼───────────────────────────────────────────────────────│ Upstream │   ┌──────────┐                                   │   │
│    900ms│HTTP response │    │                                                       │   100ms  │   │  3scale  │            async                  │   │
│         └──────────────┘    │                                                       │          │─ ▷│   500ms  │          2 threads                │   │
│         ┌──────────────┐    │                                                       └──────────┘   └──────────┘          available                │   │
│   1400ms│ HTTP request │    │                                                                                  ┌──────────┐                       │   │
│─────────┴──────────────┴────┼─────────────────────────────────────────────────────────────────────────────────▶│          │  │                    │   │
│◀────────┬──────────────┬────┼──────────────────────────────────────────────────────────────────────────────────│ Upstream │                       │   │
│   1500ms│HTTP response │    │                                                                                  │   100ms  │─ ┘                    │   │
│         └──────────────┘    │                                                                                  │          │                       │   │
└─────────────────────────────┤                                                                                  └──────────┘                       ├───┘
                              │                                                                                                                     │
                              └─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```


## Batching policy

By default, APIcast performs one call to the 3scale backend for each request
that it receives. The goal of the batching policy is to reduce latency and increase
throughput by significantly reducing the number of requests made to the 3scale
backend. In order to achieve that, this policy caches authorization statuses and
batches reports.

[This document](../gateway/src/apicast/policy/3scale_batcher/README.md) explains
the trade-offs that the 3scale batching policy makes and explains how it works
in great detail.

The diagram below illustrates how the 3scale batching policy works.

```
                                                                              ┌────────────────┐
                                                                              │    APIcast     │
                              ┌───────────────────────────────────────────────┴────────────────┴────────────────────────────────────────────────────┐
                              │                                                               ┌────┬────────────────────┬─────┐                     │
                              │                                                               │    │  batching policy   │     │                     │
┌─────────────────────────────┤                                                               │  ┌─┤  async reporting   │◀─┐  │                     │
│   TCP connection (client)   │                                                               │  │ │  every N seconds   │  │  │                     │
├─────────────────────────────┤                                                               │  │ └────────────────────┘  │  │                     │
│                             │   ┌──────────┐                                                │  │                         │  │                     │
│                             │   │  3scale  │                                                │  │                         │  │                     │
│                             │   │  500ms   │                                                │  │                         │  │                     │
│                             │   │  TTL: N  │                                      ─ ─ ─ ─ ─▷│  │                         │  │◁─                   │
│         ┌──────────────┐    │ **│ seconds  │**                                   │     │    │  │                         │  │  │                  │
│         │ HTTP request │    │ * └──────────┘ *  ┌──────────┐                                │  │      ┌──────────┐       │  │                     │
│─────────┴──────────────┴────┼─*──────────────*─▶│          │                     │     │    │  │      │  3scale  │       │  │  │                  │
│         ┌──────────────┐    │                   │ Upstream │                                │  └─────▶│   500ms  │───────┘  │                     │
│   600ms │HTTP response │    │                   │   100ms  │                     │     │    │         └──────────┘          │  │                  │
│◀────────┴──────────────┴────┼───────────────────│          │                                │                               │                     │
│         ┌──────────────┐    │                   └──────────┘                     │     │    └───────────────────────────────┘  │                  │
│   600ms │ HTTP request │    │                               ┌──────────┐                                    △                                     │
│─────────┴──────────────┴────┼──────────────────────────────▶│          │         │     │                                       │                  │
│◀────────┬──────────────┬────┼───────────────────────────────│ Upstream │                                    │                                     │
│   700ms │HTTP response │    │                               │   100ms  │         │     │                                       │                  │
│         └──────────────┘    │                               │          │─ ─ ─ ─ ─                           │                                     │
│         ┌──────────────┐    │                               └──────────┘               │                                       │                  │
│    700ms│ HTTP request │    │                                           ┌──────────┐                        │                                     │
│─────────┴──────────────┴────┼──────────────────────────────────────────▶│          │   │                                       │                  │
│◀────────┬──────────────┬────┼───────────────────────────────────────────│ Upstream │                        │                                     │
│    800ms│HTTP response │    │                                           │   100ms  │   │                                       │                  │
│         └──────────────┘    │                                           │          │─ ─                     │                                     │
└─────────────────────────────┤                                           └──────────┘                                           │                  │
┌─────────────────────────────┤                                                                               │                                     │
│   TCP connection (client)   │                                                                                                  │                  │
├─────────────────────────────┤                                                                               │                                     │
│         ┌──────────────┐    │                   ┌──────────┐                                                                   │                  │
│    500ms│ HTTP request │    │                   │          │                                                │                                     │
│─────────┴──────────────┴────┼──────────────────▶│ Upstream │                                                                   │                  │
│◀────────┬──────────────┬────┼───────────────────│   100ms  │─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┘                                     │
│    600ms│HTTP response │    │                   │          │                                                                   │                  │
│         └──────────────┘    │                   └──────────┘                                                                                      │
│         ┌──────────────┐    │                               ┌──────────┐                                                       │                  │
│    600ms│ HTTP request │    │                               │          │                                                                          │
│─────────┴──────────────┴────┼──────────────────────────────▶│ Upstream │                                                       │                  │
│◀────────┬──────────────┬────┼───────────────────────────────│   100ms  │─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─                   │
│    700ms│HTTP response │    │                               │          │                                                                          │
│         └──────────────┘    │                               └──────────┘                                                                          │
└─────────────────────────────┤                                                                                                                     │
                              │                                                                                                                     │
                              └─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```
