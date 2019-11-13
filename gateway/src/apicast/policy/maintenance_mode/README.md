# Maintenance Mode

A policy which allows you reject incoming requests with a specified status code
and message. It's useful for maintenance periods or to temporarily block an API.

## Properties

| Property                     | Default                           | Description      |
|------------------------------|-----------------------------------|------------------|
| status (integer, _optional_) | 503                               | Response code    |
| message (string, _optional_) | Service Unavailable - Maintenance | Response message |

## Example Configuration
```json
{
  "name": "maintenance-mode",
  "configuration": {
    "message": "Be back soon..",
    "status": 503
  }
}
```
