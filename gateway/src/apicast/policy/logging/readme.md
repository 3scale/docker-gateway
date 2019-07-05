# Logging policy

This policy has two primary purposes: one is to enable and disable access log
output, and the second one is to be able to create a custom access log format
for each service and be able to set conditions to write custom access log. 


## Exported variables

Liquid templating can be used on custom logging, the exported variables are:

- NGINX default log_format directive variables, as example: `{{remote_addr}}`.
[Log format documentation](http://nginx.org/en/docs/http/ngx_http_log_module.html). 

- Response and request headers using `{{req.headers.FOO}}` for getting FOO
header in the request, or `{{res.headers.FOO}}` to retrieve FOO header on
response.
- Service information, as `{{service.id}}` and all service properties as the
  `THREESCALE_CONFIG_FILE` or `THREESCALE_PORTAL_ENDPOINT` parameters provide.

## Examples

### Disable access log:

```json
{
  "name": "apicast.policy.logging",
  "configuration": {
    "enable_access_logs": false
  }
}
```

### Enable custom access log:

```json
{
  "name": "apicast.policy.logging",
  "configuration": {
    "enable_access_logs": false,
    "custom_logging": "[{{time_local}}] {{host}}:{{server_port}} {{remote_addr}}:{{remote_port}} \"{{request}}\" {{status}} {{body_bytes_sent}} ({{request_time}}) {{post_action_impact}}",
  }
}
```

### Enable custom access log with the service ID:
```json
{
  "name": "apicast.policy.logging",
  "configuration": {
    "enable_access_logs": false,
    "custom_logging": "\"{{request}}\" to service {{service.id}} and {{service.name}}",
  }
}
```

### Write access log in JSON format:

```json
{
  "name": "apicast.policy.logging",
  "configuration": {
    "enable_access_logs": false,
    "enable_json_logs": true,
    "json_object_config": [
      {
        "key": "host",
        "value": "{{host}}",
        "value_type": "liquid"
      },
      {
        "key": "time",
        "value": "{{time_local}}",
        "value_type": "liquid"
      },
      {
        "key": "custom",
        "value": "custom_method",
        "value_type": "plain"
      }
    ]
  }
}
```

### Write a custom access log only for a successful request.

```json
{
  "name": "apicast.policy.logging",
  "configuration": {
    "enable_access_logs": false,
    "custom_logging": "\"{{request}}\" to service {{service.id}} and {{service.name}}",
    "condition": {
      "operations": [
        {"op": "==", "match": "{{status}}", "match_type": "liquid", "value": "200"}
      ],
      "combine_op": "and"
    }
  }
}
```

### Write a custom access log where reponse status match 200 or 500.

```json
{
  "name": "apicast.policy.logging",
  "configuration": {
    "enable_access_logs": false,
    "custom_logging": "\"{{request}}\" to service {{service.id}} and {{service.name}}",
    "condition": {
      "operations": [
        {"op": "==", "match": "{{status}}", "match_type": "liquid", "value": "200"},
        {"op": "==", "match": "{{status}}", "match_type": "liquid", "value": "500"}
      ],
      "combine_op": "or"
    }
  }
}
```

## Caveats

- If `custom_logging` or `enable_json_logs` property is enabled, default access
  log will be dissabled.
- If `enable_json_logs` is enabled, `custom_logging` field will be omitted

## Global configuration for all services. 

Logging options can be useful in all services, to avoid having issues with logs
that are not correctly formated in other services, a custom Apicast environment
can be set and all services will implement a specifc policy, in this case
logging.

Here is an example of a policy that is loaded in all services: 

custom_env.lua
```
local cjson = require('cjson')
local PolicyChain = require('apicast.policy_chain')
local policy_chain = context.policy_chain

local logging_policy_config = cjson.decode([[
{
  "enable_access_logs": false,
  "custom_logging": "\"{{request}}\" to service {{service.id}} and {{service.name}}"
}
]])

policy_chain:insert( PolicyChain.load_policy('logging', 'builtin', logging_policy_config), 1) 

return {
  policy_chain = policy_chain,
  port = { metrics = 9421 },
}
```

To run Apicast with this specific environment: 

```
docker run --name apicast --rm -p 8080:8080 \
    -v $(pwd):/config \
    -e APICAST_ENVIRONMENT=/config/custom_env.lua \
    -e THREESCALE_PORTAL_ENDPOINT=https://ACCESS_TOKEN@ADMIN_PORTAL_DOMAIN \
    quay.io/3scale/apicast:master
```

Key concepts of the docker command: 
  - Current lua file need to be shared to the container `-v $(pwd):/config`
  - `APICAST_ENVIRONMENT` variable need to be set to the lua file that is
    stored on `/config` directory.
