# Maintenance Mode

A policy which allows you reject incoming requests with a specified status code and message. It's useful for maintenance periods or to temporarily block an API.

## Properties

The following is a list of possible properties and default values.

Property name         | Default           | Description     |
--------------------|------------------|-----------------------|
status (integer, _optional_)				| 503   | Response code    |
message (string, _optional_)      		| 503 Service Unavailable - Maintenance   |  Response message  |

## Example Configuration
```json
{
  "policy_chain": [
    {"name": "maintenance-mode", "version": "1.0.0",
    "configuration": {"message": "Be back soon..", "status": 503} },
  ]
}

```
