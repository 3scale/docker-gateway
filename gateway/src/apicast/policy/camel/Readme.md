#  Camel proxy policy

You can use this policy to define an Apache Camel proxy where the traffic is sent 
over the defined proxy. The example traffic flow is as follows:

```
   ,-.
   `-'
   /|\
    |            ,-------.          ,---------.          ,----------.
   / \           |APIcast|          |  CAMEL  |          |APIBackend|
  User           `---+---'          `----+----'          `----------'
   |  GET /resource  |                   |                    |
   | --------------->|                   |                    |
   |                 |                   |                    |
   |                 |  Get /resource    |                    |
   |                 |------------------>|                    |
   |                 |                   |                    |
   |                 |                   |  Get /resource/    |
   |                 |                   | - - - - - - - - - >|
   |                 |                   |                    |
   |                 |                   |     response       |
   |                 |                   |<- - - - - - - - - -|
   |                 |                   |                    |
   |                 |     response      |                    |
   |                 |<------------------|                    |
   |                 |                   |                    |
   |                 |                   |                    |
   | <---------------|                   |                    |
  User           ,---+---.          ,----+----.          ,----------.
   ,-.           |APIcast|          |  CAMEL  |          |APIBackend|
   `-'           `-------'          `---------'          `----------'
   /|\
    |
   / \
```


## Configuration

```
"policy_chain": [
    {
      "name": "apicast.policy.apicast"
    },
    {
      "name": "apicast.policy.camel",
      "configuration": {
          "http_proxy": "http://192.168.15.103:8080/",
          "https_proxy": "http://192.168.15.103:8443/",
          "all_proxy": "http://192.168.15.103:8080/"
      }
    }
]
```

- If `http_proxy` or `https_proxy` is not defined, the `all_proxy` setting is used. 

## Caveats

- This policy will disable all load-balancing policies and traffic will be
  always sent to the proxy. 
- If the `HTTP_PROXY`, `HTTPS_PROXY` or `ALL_PROXY` parameters are defined, this
  policy will overwrite those values. 
- Proxy connection does not support authentication. If you need authentication, 
please use the headers policy.


## Example use case

This policy is designed to to apply more fined-grained policies and transformation 
using Apache Camel.

This [example project](https://github.com/zregvart/camel-netty-proxy) shows an 
HTTP proxy that transforms the response body from the API
backend to uppercase. 
