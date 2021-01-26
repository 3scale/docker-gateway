# Maintenance Mode

A policy which allows you reject incoming requests with a specified status code
and message. It's useful for maintenance periods or to temporarily block an API.

## Properties

| Property                     | Default                           | Description      |
|------------------------------|-----------------------------------|------------------|
| status (integer, _optional_) | 503                               | Response code    |
| message (string, _optional_) | Service Unavailable - Maintenance | Response message |

## Examples Configuration

- Custom response message
```json
{
  "name": "maintenance-mode",
  "configuration": {
    "message": "Be back soon..",
    "status": 503
  }
}
```
- Apply Maintenance Mode for a specific upstream
```json
{
    "name": "maintenance_mode",
    "configuration": {
      "condition": {
        "operations": [
          {
            "left_type": "liquid",
            "right_type": "plain",
            "left": "{{ upstream.host }}{{ upstream.path }}",
            "right": "echo-api.3scale.net/test",
            "op": "=="
          }
        ],
        "combine_op": "and"
      },
      "status": 503,
      "message": "Echo API /test is currently Unavailable"
    }
}
```