# StatusCode overwrite

This policy changes the upstream status code with the desired ones.

## Examples

Change status 200 to 201

```
{
  "name": "statuscode_overwrite",
  "version": "builtin",
  "configuration": {
    "http_codes": [
      {
        "upstream": 200,
        "apicast": 201
      }
    ]
  }
}
```
