# Request/response payload size limits policy

This policy allows users to limit the size of the request and the response.

To get this policy working, the content-length header is mandatory on request
and response.

## Configuration

- Limit request to 100 bytes, response unlimited

```
{
  "name": "apicast.policy.limits",
  "configuration": {
    "request": 100,
    "response": 0
  }
}
```

- Limit response to 100 bytes, request unlimited

```
{
  "name": "apicast.policy.limits",
  "configuration": {
    "request": 0,
    "response": 100
  }
}
```
