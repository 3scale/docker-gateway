# JWT claim Check Policy

This policy allows users to define new rules based on any JSON Web Token(JWT)
claim, resource target and the method that the user is interested in blocking.
 
## Caveats

In order to be able to route based on the value of a jwt claim, there needs to
be a policy in the chain that validates the jwt and stores it in the context
that the policies share.

If the policy is blocking a resource and a method, this will also validate the
JWT operations, but in case that the method resource does not match, the request
will continue to the backend API. 

Example: 
```
{
  "name": "apicast.policy.jwt_claim_check",
  "configuration": {
      "error_message": "Invalid JWT check",
      "rules": [
          {
              "operations": [
                  {"op": "==", "jwt_claim": "role", "jwt_claim_type": "plain", "value": "admin"}
              ],
              "combine_op":"and",
              "methods": ["GET"],
              "resource": "/resource", 
              "resource_type": "plain"
          }
      ]
  }
}
```

In this case, any non GET request will not validate the JWT operations, so POST
resource will be allowed without JWT constraint.

In case of a GET request, the JWT needs to have the role claim as admin, if not
the request will be denied. 

## Examples

- When you want to allow those who have the jwt claim role `role1` to access `/resource`.

```json
{
  "name": "apicast.policy.jwt_claim_check",
  "configuration": {
      "error_message": "Invalid JWT check",
      "rules": [
          {
              "operations": [
                  {"op": "==", "jwt_claim": "role", "jwt_claim_type": "plain", "value": "role1"}
              ],
              "combine_op":"and",
              "methods": ["ANY"],
              "resource": "/resource", 
              "resource_type": "plain"
          }
      ]
  }
}
```

- When you want to allow those who have the jwt claim role `role1` and `role2` to
  access `/resource`, a OR clause in combine operations field can be used.

```json
{
  "name": "apicast.policy.jwt_claim_check",
  "configuration": {
      "error_message": "Invalid JWT check",
      "rules": [
          {
              "operations": [
                  {"op": "==", "jwt_claim": "role", "jwt_claim_type": "plain", "value": "role1"},
                  {"op": "==", "jwt_claim": "role", "jwt_claim_type": "plain", "value": "role2"}
              ],
              "combine_op":"or",
              "methods": ["ANY"],
              "resource": "/resource", 
              "resource_type": "plain"
          }
      ]
  }
}
```

- When you want to allow those who have the client role including the client ID
  of the application client (the recipient of the access token) to access
  `/resource`. Set the `jwt_claim_type` to `liquid` to specify the JWT
  information to the `name` of the client role.

```json
{
  "name": "apicast.policy.jwt_claim_check",
  "configuration": {
      "error_message": "Invalid JWT check",
      "rules": [
          {
              "operations": [
                  {"op": "==", "jwt_claim": "role_{{aud}}", "jwt_claim_type": "liquid", "value": "client1"}
              ],
              "combine_op":"and",
              "methods": ["ANY"],
              "resource": "/resource", 
              "resource_type": "plain"
          }
      ]
  }
}
```

- When you want to allow those who have who have the client `client1`'s role
  `role1` to access the resource including the application client ID. Use the
  `"liquid"` to specify the JWT information to the `"resource"`.

```json
{
  "name": "apicast.policy.jwt_claim_check",
  "configuration": {
      "error_message": "Invalid JWT check",
      "rules": [
          {
              "operations": [
                  {"op": "==", "jwt_claim": "role", "jwt_claim_type": "plain", "value": "client1"}
              ],
              "combine_op": "and",
              "methods": ["ANY"],
              "resource": "/resource_{{jwt.aud}}", 
              "resource_type": "liquid"
          }
      ]
  }
}
```

- When you want to allow those who have who have role admin and belongs to
  fooApplication audience to `resource/` multiple operations can be specified.

```json
{
  "name": "apicast.policy.jwt_claim_check",
  "configuration": {
      "error_message": "Invalid JWT check",
      "rules": [
          {
              "operations": [
                  {"op": "==", "jwt_claim": "role", "jwt_claim_type": "plain", "value": "client1"},
                  {"op": "==", "jwt_claim": "aud", "jwt_claim_type": "plain", "value": "fooApplication"}
              ],
              "combine_op": "and",
              "methods": ["ANY"],
              "resource": "/resource", 
              "resource_type": "plain"
          }
      ]
  }
}
```
