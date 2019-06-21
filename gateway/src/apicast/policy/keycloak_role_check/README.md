# Keycloak Role Check Policy

## Examples

- When you want to allow those who have the realm role `role1` to access `/resource1`.

  ```json
  {
    "scopes": [
      {
        "realm_roles": [ { "name": "role1" } ],
        "resource": "/resource1"
      }
    ]
  }
  ```

- When you want to allow those who have the client `client1`'s role `role1` to access `/resource1`.

  ```json
  {
    "scopes": [
      {
        "client_roles": [ { "name": "role1", "client": "client1" } ],
        "resource": "/resource1"
      }
    ]
  }
  ```

- When you want to allow those who don't have the realm role `role1` to access `/resource1`. Specify the `"blacklist"`.

  ```json
  {
    "scopes": [
      {
        "realm_roles": [ { "name": "role1" } ],
        "resource": "/resource1"
      }
    ],
    "type": "blacklist"
  }
  ```

- When you want to allow those who have the realm role `role1` and `role2` to access `/resource1`. Specity the roles in the `"realm_roles"`.

  ```json
  {
    "scopes": [
      {
        "realm_roles": [ { "name": "role1" }, { "name": "role2" } ],
        "resource": "/resource1"
      }
    ]
  }
  ```

- When you want to allow those who have the realm role `role1` or `role2` to access `/resource1`. Specify the scope for each role.

  ```json
  {
    "scopes": [
      { "realm_roles": [ { "name": "role1" } ], "resource": "/resource1" },
      { "realm_roles": [ { "name": "role2" } ], "resource": "/resource1" }
    ]
  }
  ```

- When you want to allow those who have the client role `role1` of the application client (the recipient of the access token) to access `/resource1`. Use the `"liquid"` to specify the JWT information to the `"client"`.

  ```json
  {
    "scopes": [
      {
        "client_roles": [ { "name": "role1", "client": "{{ jwt.aud }}", "client_type": "liquid" } ],
        "resource": "/resource1"
      }
    ]
  }
  ```

- When you want to allow those who have the client role including the client ID of the application client (the recipient of the access token) to access `/resource1`. Use the `"liquid"` to specify the JWT information to the `"name"` of the client role.

  ```json
  {
    "scopes": [
      {
        "client_roles": [ { "name": "role_{{ jwt.aud }}", "name_type": "liquid", "client": "client1" } ],
        "resource": "/resource1"
      }
    ]
  }
  ```

- When you want to allow those who have who have the client `client1`'s role `role1` to access the resource including the application client ID. Use the `"liquid"` to specify the JWT information to the `"resource"`.

  ```json
  {
    "scopes": [
      {
        "client_roles": [ { "name": "role1", "client": "client1" } ],
        "resource": "/resource_{{ jwt.aud }}", "resource_type": "liquid"
      }
    ]
  }
  ```

- When you want to allow those who have the realm role `role1` to access `/resource1` and only methods GET and POST.

  ```json
  {
    "scopes": [
      {
        "realm_roles": [ { "name": "role1" } ],
        "resource": "/resource1",
        "methods": ["GET", "POST"]
      }
    ]
  }
  ```
