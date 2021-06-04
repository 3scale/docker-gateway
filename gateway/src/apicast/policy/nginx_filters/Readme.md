# Nginx Filters policy

## Description

Nginx, by default, checks/validates some request headers. This policy allows the
user to skips these checks and sends them to the upstream servers. 

The primary use case is like If-Match headers, where Nginx filters by default,
but some users want these headers on the upstream server because Nginx is not
responsible for this header. 

There is an option to delete it or to append it to the upstream server. 

## Warning

If one header is also managed by the multiple headers policy, this can cause
conflicts.


## Examples

Send If-Match header to the upstream server, and avoid Nginx 412 response:

```
{ "name": "apicast.policy.nginx_filters",
  "configuration": {
    "headers": [
      {"name": "If-Match", "append": true}
    ]
  }
}
```


Delete If-Match header and avoid the Nginx 412 response:

```
{ "name": "apicast.policy.nginx_filters",
  "configuration": {
    "headers": [
      {"name": "If-Match", "append": false}
    ]
  }
}
```
