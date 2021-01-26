# Prometheus metrics

| Metric                             | Description                                                      | Type      | Labels                                                            | Policy          |
|------------------------------------|------------------------------------------------------------------|-----------|-------------------------------------------------------------------|-----------------|
| apicast_status                     | Number of response status send by APIcast to client              | counter   | status                                                            | Default         |
| nginx_http_connections             | Number of HTTP connections                                       | gauge     | state(accepted,active,handled,reading,total,waiting,writing)      | Default         |
| nginx_error_log                    | APIcast errors                                                   | counter   | level(debug,info,notice,warn,error,crit,alert,emerg)              | Default         |
| openresty_shdict_capacity          | Capacity of the dictionaries shared between workers              | gauge     | dict(one for every dictionary)                                    | Default         |
| openresty_shdict_free_space        | Free space of the dictionaries shared between workers            | gauge     | dict(one for every dictionary)                                    | Default         |
| nginx_metric_errors_total          | Number of errors of the Lua library that manages the metrics     | counter   | -                                                                 | Default         |
| total_response_time_seconds        | Time needed to sent a response to the client (in seconds)        | histogram | service_id, service_system_name                                   | Default         |
| upstream_response_time_seconds     | Response times from upstream servers (in seconds)                | histogram | service_id, service_system_name                                   | Default         |
| upstream_status                    | HTTP status from upstream servers                                | counter   | status, service_id, service_system_name                           | Default         |
| worker_process                     | Number of times that a worker process has been started.          | counter   | -                                                                 | Default         |
| threescale_backend_calls           | Authorize and report requests to the 3scale backend (Apisonator) | counter   | endpoint(authrep, auth, report), status(2xx, 4xx, 5xx)            | APIcast         |
| batching_policy_auths_cache_hits   | Hits in the auths cache of the 3scale batching policy            | counter   | -                                                                 | 3scale Batcher  |
| batching_policy_auths_cache_misses | Misses in the auths cache of the 3scale batching policy          | counter   | -                                                                 | 3scale Batcher  |
| content_caching                    | Number of requests that go through content caching policy.       | counter   | status(MISS, BYPASS, EXPIRED, STALE, UPDATING, REVALIDATED, HIT)  | Content Caching |
