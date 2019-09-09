# Routing policy

- [**Description**](#description)
- [**Rule that uses the request path**](#rule-that-uses-the-request-path)
- [**Rule that uses a header**](#rule-that-uses-a-header)
- [**Rule that uses a query argument**](#rule-that-uses-a-query-argument)
- [**Rule that uses a jwt claim**](#rule-that-uses-a-jwt-claim)
- [**Rule with several operations**](#rule-with-several-operations)
- [**Combining rules**](#combining-rules)
- [**"Catch-all" rules**](#catch-all-rules)
- [**Supported operations**](#supported-operations)
- [**Liquid templating**](#liquid-templating)
- [**Set the host used in the Host header**](#set-the-host-used-in-the-host-header)

## Description

This policy allows to modify the upstream (scheme, host, and port) of a request
based on:

- The request path
- A header
- A query argument
- A jwt claim

When combined with the APIcast policy, the routing policy should be placed
before the APIcast one in the chain. The reason is that whichever of those 2
policies comes first will output content to the response. When the second gets a
change to run its content phase, the request will already be sent to the client,
so it will not output anything to the response.

## Rule that uses the request path

This is a configuration that routes to `http://example.com` when the path is
`/accounts`:

```json
  {
    "name": "routing",
    "version": "builtin",
    "configuration": {
      "rules": [
        {
          "url": "http://example.com",
          "condition": {
            "operations": [
              {
                "match": "path",
                "op": "==",
                "value": "/accounts"
              }
            ]
          }
        }
      ]
    }
  }
```

## Rule that uses a header

This is a configuration that routes to `http://example.com` when the value of
the header `Test-Header` is `123`:

```json
  {
    "name": "routing",
    "version": "builtin",
    "configuration": {
      "rules": [
        {
          "url": "http://example.com",
          "condition": {
            "operations": [
              {
                "match": "header",
                "header_name": "Test-Header",
                "op": "==",
                "value": "123"
              }
            ]
          }
        }
      ]
    }
  }
```

## Rule that uses a query argument

This is a configuration that routes to `http://example.com` when the value of
the query argument `test_query_arg` is `123`:

```json
  {
    "name": "routing",
    "version": "builtin",
    "configuration": {
      "rules": [
        {
          "url": "http://example.com",
          "condition": {
            "operations": [
              {
                "match": "query_arg",
                "query_arg_name": "test_query_arg",
                "op": "==",
                "value": "123"
              }
            ]
          }
        }
      ]
    }
  }
```

## Rule that uses a jwt claim

In order to be able to route based on the value of a jwt claim, there needs to
be a policy in the chain that validates the jwt and stores it in the context
that the policies share.

This is a configuration that routes to `http://example.com` when the value of
the jwt claim `test_claim` is `123`:

```json
  {
    "name": "routing",
    "version": "builtin",
    "configuration": {
      "rules": [
        {
          "url": "http://example.com",
          "condition": {
            "operations": [
              {
                "match": "jwt_claim",
                "jwt_claim_name": "test_claim",
                "op": "==",
                "value": "123"
              }
            ]
          }
        }
      ]
    }
  }
```

## Rule with several operations

Rules can have several operations and route to the given upstream only when all
of them evaluate to true (using the 'and' `combine_op`), or when at least one of
them evaluates to true (using the 'or' `combine_op`). The default value of
`combine_op` is 'and'.

This is a configuration that routes to `http://example.com` when the path of the
request is `/accounts` and when the value of the header `Test-Header` is `123`:

```json
  {
    "name": "routing",
    "version": "builtin",
    "configuration": {
      "rules": [
        {
          "url": "http://example.com",
          "condition": {
            "combine_op": "and",
            "operations": [
              {
                "match": "path",
                "op": "==",
                "value": "/accounts"
              },
              {
                "match": "header",
                "header_name": "Test-Header",
                "op": "==",
                "value": "123"
              }
            ]
          }
        }
      ]
    }
  }
```

This is a configuration that routes to `http://example.com` when the path of the
request is `/accounts` or when the value of the header `Test-Header` is `123`:

```json
  {
    "name": "routing",
    "version": "builtin",
    "configuration": {
      "rules": [
        {
          "url": "http://example.com",
          "condition": {
            "combine_op": "or",
            "operations": [
              {
                "match": "path",
                "op": "==",
                "value": "/accounts"
              },
              {
                "match": "header",
                "header_name": "Test-Header",
                "op": "==",
                "value": "123"
              }
            ]
          }
        }
      ]
    }
  }
```

## Combining rules

Rules can be combined. When there are several of them, the upstream selected is
the one of the first rule that evaluates to true.

This is a configuration with several rules:
```json
  {
    "name": "routing",
    "version": "builtin",
    "configuration": {
      "rules": [
        {
          "url": "http://some_upstream.com",
          "condition": {
            "operations": [
              {
                "match": "path",
                "op": "==",
                "value": "/accounts"
              }
            ]
          }
        },
        {
          "url": "http://another_upstream.com",
          "condition": {
            "operations": [
              {
                "match": "path",
                "op": "==",
                "value": "/users"
              }
            ]
          }
        }
      ]
    }
  }
```

## "Catch-all" rules

A rule without operations always matches. This can be useful to define
"catch-all" rules. Here's a configuration that routes the request to
`http://some_upstream.com` if the path is `/abc`, routes the request to
`http://another_upstream.com` if the path is `/def`, and finally, routes the
request to `http://default_upstream.com` if none of the previous rules evaluated
to true:
```json
  {
    "name": "routing",
    "version": "builtin",
    "configuration": {
      "rules": [
        {
          "url": "http://some_upstream.com",
          "condition": {
            "operations": [
              {
                "match": "path",
                "op": "==",
                "value": "/abc"
              }
            ]
          }
        },
        {
          "url": "http://another_upstream.com",
          "condition": {
            "operations": [
              {
                "match": "path",
                "op": "==",
                "value": "/def"
              }
            ]
          }
        },
        {
          "url": "http://default_upstream.com",
          "condition": {
            "operations": []
          }
        }
      ]
    }
  }
```

## Supported operations

The supported operations are `==`, `!=`, and `matches`. The latter matches a
string with a regular expression and it is implemented using
[ngx.re.match](https://github.com/openresty/lua-nginx-module#ngxrematch)

This is a configuration that uses `!=`. It routes to `http://example.com` when
the path is not `/accounts`:
```json
  {
    "name": "routing",
    "version": "builtin",
    "configuration": {
      "rules": [
        {
          "url": "http://example.com",
          "condition": {
            "operations": [
              {
                "match": "path",
                "op": "!=",
                "value": "/accounts"
              }
            ]
          }
        }
      ]
    }
  }
```
## Liquid templating on match

It is possible to use liquid templating in the match section. This allows to
define rules with dynamic information and provide a way to match with any
request info.

```json
  {
    "name": "routing",
    "version": "builtin",
    "configuration": {
      "rules": [
        {
          "url": "http://example.com",
          "condition": {
            "operations": [
              {
                "match": "liquid",
                "liquid_value": "{{original_request.path}}",
                "op": "matches",
                "value": "/bridge-1"
              }
            ]
          }
        }
      ]
    }
  }
```

## Liquid templating

It is possible to use liquid templating for the values of the configuration.
This allows to define rules with dynamic values. Suppose that a policy in the
chain stores the key `my_var` in the context. As an example, this is a
configuration that uses that value to route the request:
```json
  {
    "name": "routing",
    "version": "builtin",
    "configuration": {
      "rules": [
        {
          "url": "http://example.com",
          "condition": {
            "operations": [
              {
                "match": "header",
                "header_name": "Test-Header",
                "op": "==",
                "value": "{{ my_var }}",
                "value_type": "liquid"
              }
            ]
          }
        }
      ]
    }
  }
```

## Set the host used in the Host header

By default, when a request is routed, the policy sets the Host header using the
host of the URL of the rule that matched. However, it is possible to specify a
different host with the `host_header` attribute. As an example, this is a
config that specifies `some_host.com` as the host of the Host header:
```json
  {
    "name": "routing",
    "version": "builtin",
    "configuration": {
      "rules": [
        {
          "url": "http://example.com",
          "host_header": "some_host.com",
          "condition": {
            "operations": [
              {
                "match": "path",
                "op": "==",
                "value": "/"
              }
            ]
          }
        }
      ]
    }
  }
```
