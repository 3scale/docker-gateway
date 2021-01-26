# Custom metrics policies

This policy adds the availability to add metrics after the Upstream API
response.  The main use case for this policy is to add metrics based on response
code status, headers or different Nginx variables.

## Caveats:

- When auth happens before request send to Upstream API, a second call to
  backend will be made to report the new metrics to the UpstreamAPI.
- This policy does not work with batching policy.
- Metrics need to be created in the admin portal before submit it.

## Request flow

```
     ┌────┐          ┌───────┐                                                       ┌──────────┐          ┌───────────┐     
     │User│          │APICast│                                                       │APIsonator│          │UpstreamAPI│     
     └─┬──┘          └───┬───┘                                                       └────┬─────┘          └─────┬─────┘     
       │                 │                                                                │                      │           
       │                 │                   ╔═════════════════════════════════╗          │                      │           
═══════╪═════════════════╪═══════════════════╣ First request (Auth not cached) ╠══════════╪══════════════════════╪═══════════
       │                 │                   ╚═════════════════════════════════╝          │                      │           
       │                 │                                                                │                      │           
       │    Get /foo     │                                                                │                      │           
       │ ───────────────>│                                                                │                      │           
       │                 │                                                                │                      │           
       │                 │       POST  /transactions/authrep.xml Metrics: {"Hit":1}       │                      │           
       │                 │ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─>                      │           
       │                 │                                                                │                      │           
       │                 │                             200 OK                             │                      │           
       │                 │<─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─                       │           
       │                 │                                                                │                      │           
       │                 │                                       Get /foo                 │                      │           
       │                 │──────────────────────────────────────────────────────────────────────────────────────>│           
       │                 │                                                                │                      │           
       │                 │                                        200 OK                  │                      │           
       │                 │<──────────────────────────────────────────────────────────────────────────────────────│           
       │                 │                                                                │                      │           
       │     200 OK      │                                                                │                      │           
       │ <───────────────│                                                                │                      │           
       │                 │                                                                │                      │           
       │                 │         POST /transactions.xml Metrics: {"Hit.200": 1}         │                      │           
       │                 │ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─>                      │           
       │                 │                                                                │                      │           
       │                 │                             200 OK                             │                      │           
       │                 │<─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─                       │           
       │                 │                                                                │                      │           
       │                 │                                                                │                      │           
       │                 │                    ╔══════════════════════════════╗            │                      │           
═══════╪═════════════════╪════════════════════╣ Second request (Auth cached) ╠════════════╪══════════════════════╪═══════════
       │                 │                    ╚══════════════════════════════╝            │                      │           
       │                 │                                                                │                      │           
       │    Get /foo     │                                                                │                      │           
       │ ───────────────>│                                                                │                      │           
       │                 │                                                                │                      │           
       │                 │                                       Get /foo                 │                      │           
       │                 │──────────────────────────────────────────────────────────────────────────────────────>│           
       │                 │                                                                │                      │           
       │                 │                                        200 OK                  │                      │           
       │                 │<──────────────────────────────────────────────────────────────────────────────────────│           
       │                 │                                                                │                      │           
       │     200 OK      │                                                                │                      │           
       │ <───────────────│                                                                │                      │           
       │                 │                                                                │                      │           
       │                 │POST  /transactions/authrep.xml Metrics: {"Hit":1, "Hit.200": 1}│                      │           
       │                 │ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─>                      │           
       │                 │                                                                │                      │           
       │                 │                             200 OK                             │                      │           
       │                 │<─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─                       │           
     ┌─┴──┐          ┌───┴───┐                                                       ┌────┴─────┐          ┌─────┴─────┐     
     │User│          │APICast│                                                       │APIsonator│          │UpstreamAPI│     
     └────┘          └───────┘                                                       └──────────┘          └───────────┘     
```


## Configuration examples

This policy increments the metric error, by the header increment, if the
Upstream API returns a 400 status:

```
{
  "name": "apicast.policy.custom_metrics",
  "configuration": {
    "rules": [
      {
        "metric": "error",
        "increment": "{{ resp.headers['increment'] }}",
        "condition": {
          "operations": [
            {
              "right": "{{status}}",
              "right_type": "liquid",
              "left": "400",
              "op": "=="
            }
          ],
          "combine_op": "and"
        }
      }
    ]
  }
}
```

Increment the `hits` metric with the information status_code information if the
Upstream API return a 200 status:

```
{
  "name": "apicast.policy.custom_metrics",
  "configuration": {
    "rules": [
      {
        "metric": "hits_{{status}}",
        "increment": "1",
        "condition": {
          "operations": [
            {
              "right": "{{status}}",
              "right_type": "liquid",
              "left": "200",
              "op": "=="
            }
          ],
          "combine_op": "and"
        }
      }
    ]
  }
}
```



## Dev notes:


Flow source code:

```
@startuml
== First request (Auth not cached) ==
User -> APICast: Get /foo
APICast --> APIsonator: POST  /transactions/authrep.xml
APIsonator --> APICast: 200 OK
APICast -> UpstreamAPI: Get /foo
UpstreamAPI -> APICast: 200 OK
APICast ->User: 200 OK
APICast --> APIsonator: POST /transactions.xml
APIsonator --> APICast: 200 OK

== Second request (Auth cached) ==
User -> APICast: Get /foo
APICast -> UpstreamAPI: Get /foo
UpstreamAPI -> APICast: 200 OK
APICast ->User: 200 OK
APICast --> APIsonator: POST  /transactions/authrep.xml
APIsonator --> APICast: 200 OK

@enduml
```
