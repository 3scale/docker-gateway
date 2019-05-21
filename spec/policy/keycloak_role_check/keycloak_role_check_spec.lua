local KeycloakRoleCheckPolicy = require('apicast.policy.keycloak_role_check')
local ngx_variable = require('apicast.policy.ngx_variable')

describe('Keycloak Role check policy', function()

  before_each(function()
    ngx.header = {}
    stub(ngx, 'print')

    stub(ngx.req, 'get_method', function() return 'GET' end)
    -- avoid stubbing all the ngx.var.* and ngx.req.* in the available context
    stub(ngx_variable, 'available_context', function(context) return context end)
  end)

  describe('.access', function()
    describe('with whitelist', function()
      describe('check succeeds', function()
        it('when realm role matches the one in jwt', function()
          local role_check_policy = KeycloakRoleCheckPolicy.new({
            scopes = {
              {
                realm_roles = { { name = "aaa" } },
                resource = "/bbb"
              }
            }
          })

          ngx.var = {
            uri = '/bbb'
          }

          local context = {
            jwt = {
              realm_access = {
                roles = { "aaa" }
              }
            }
          }

          role_check_policy:access(context)
          assert.not_same(ngx.status, 403)
        end)

        it('when client role matches the one in jwt', function()
          local role_check_policy = KeycloakRoleCheckPolicy.new({
            scopes = {
              {
                client_roles = { { name = "aaa", client = "ccc" } },
                resource = "/bbb"
              }
            }
          })

          ngx.var = {
            uri = '/bbb'
          }

          local context = {
            jwt = {
              resource_access = {
                ccc = {
                  roles = { "aaa" }
                }
              }
            }
          }

          role_check_policy:access(context)
          assert.not_same(ngx.status, 403)
        end)

        it('when client role using liquid matches the one in jwt', function()
          local role_check_policy = KeycloakRoleCheckPolicy.new({
            scopes = {
              {
                client_roles = {
                  {
                    name = "{{ jwt.aud }}", name_type = "liquid",
                    client = "{{ jwt.aud }}", client_type = "liquid",
                  }
                },
                resource = "/{{ jwt.aud }}", resource_type = "liquid"
              }
            }
          })

          ngx.var = {
            uri = '/ccc'
          }

          local context = {
            jwt = {
              aud = "ccc",
              resource_access = {
                ccc = {
                  roles = { "ccc" }
                }
              }
            }
          }

          role_check_policy:access(context)
          assert.not_same(ngx.status, 403)
        end)

        it('when multi roles match the ones in jwt', function()
          local role_check_policy = KeycloakRoleCheckPolicy.new({
            scopes = {
              {
                realm_roles = { { name = "ddd" } },
                client_roles = { { name = "aaa", client = "ccc" } },
                resource = "/bbb"
              }
            }
          })

          ngx.var = {
            uri = '/bbb'
          }

          local context = {
            jwt = {
              realm_access = {
                roles = {"ddd", "eee"}
              },
              resource_access = {
                ccc = {
                  roles = { "aaa" }
                }
              }
            }
          }

          role_check_policy:access(context)
          assert.not_same(ngx.status, 403)
        end)

        it('when client role using wildcard matches the one in jwt', function()
          local role_check_policy = KeycloakRoleCheckPolicy.new({
            scopes = {
              {
                client_roles = { { name = "aaa", client = "client" } },
                resource = "/{wildcard}/client"
              }
            }
          })

          ngx.var = {
            uri = '/group-10/client/resources'
          }

          local context = {
            jwt = {
              resource_access = {
                client = {
                  roles = { "aaa", "other_role" }
                }
              }
            }
          }

          role_check_policy:access(context)
          assert.not_same(ngx.status, 403)
        end)

        it('when roles of one of multi scopes match the ones in jwt', function()
          local role_check_policy = KeycloakRoleCheckPolicy.new({
            scopes = {
              {
                client_roles = { { name = "role_of_known_client", client = "known_client" } },
                resource = "/not-accessed/"
              },
              {
                realm_roles = { { name = "unknown_role" } },
                client_roles = { { name = "role_of_known_client", client = "unknown_client" } },
                resource = "/account-a"
              },
              {
                realm_roles = { { name = "known_role" } },
                resource = "/account-a"
              },
              {
                realm_roles = { { name = "unknown_role" } },
                resource = "/{wildcard}/account-b"
              },
              {
                client_roles = { { name = "role_of_known_client", client = "known_client" } },
                resource = "/group-{wildcard}/account-b"
              }
            }
          })

          local context = {
            jwt = {
              realm_access = {
                roles = { "known_role" }
              },
              resource_access = {
                known_client = {
                  roles = { "role_of_known_client" }
                }
              }
            },
            service = {
              auth_failed_status = 403,
              error_auth_failed = "auth failed"
            }
          }

          ngx.var = {
            uri = '/account-a'
          }

          role_check_policy:access(context)
          assert.not_same(ngx.status, 403)

          ngx.var = {
            uri = '/group-a/account-b'
          }

          role_check_policy:access(context)
          assert.not_same(ngx.status, 403)
        end)
      end)

      describe('check fails', function()
        local role_check_policy
        local context

        before_each(function()
          role_check_policy = KeycloakRoleCheckPolicy.new({
            scopes = {
              {
                client_roles = { { name = "role_of_known_client", client = "known_client" } },
                resource = "/match"
              },
              {
                client_roles = { { name = "role_of_known_client", client = "unknown_client" } },
                resource = "/no-role-resource"
              },
              {
                realm_roles = { { name = "known_role" }, { name = "unknown_role" } },
                resource = "/not-enough-roles-resource"
              },
            }
          })

          context = {
            jwt = {
              realm_access = {
                roles = { "known_role" }
              },
              resource_access = {
                known_client = {
                  roles = { "role_of_known_client" }
                }
              }
            },
            service = {
              auth_failed_status = 403,
              error_auth_failed = "auth failed"
            }
          }
        end)

        it('when resource does not match the uri', function()
          ngx.var = {
            uri = '/not-match'
          }

          role_check_policy:access(context)
          assert.same(ngx.status, 403)
        end)

        it('when there is not the matched role in jwt', function()
          ngx.var = {
            uri = '/no-role-resource'
          }

          role_check_policy:access(context)
          assert.same(ngx.status, 403)
        end)

        it('when there are not enough roles in jwt', function()
          ngx.var = {
            uri = '/not-enough-roles-resource'
          }

          role_check_policy:access(context)
          assert.same(ngx.status, 403)
        end)

        it('when jwt does not exist', function()
          ngx.var = {
            uri = '/match'
          }

          context = {
            service = {
              auth_failed_status = 403,
              error_auth_failed = "auth failed"
            }
          }

          role_check_policy:access(context)
          assert.same(ngx.status, 403)
        end)
      end)
    end)

    describe('with blacklist', function()
      describe('check fails', function()
        it('when realm role matches the one in jwt', function()
          local role_check_policy = KeycloakRoleCheckPolicy.new({
            scopes = {
              {
                realm_roles = { { name = "aaa" } },
                resource = "/bbb"
              }
            },
            type = "blacklist"
          })

          ngx.var = {
            uri = '/bbb'
          }

          local context = {
            jwt = {
              realm_access = {
                roles = { "aaa" }
              }
            },
            service = {
              auth_failed_status = 403,
              error_auth_failed = "auth failed"
            }
          }

          role_check_policy:access(context)
          assert.same(ngx.status, 403)
        end)

        it('when client role matches the one in jwt', function()
          local role_check_policy = KeycloakRoleCheckPolicy.new({
            scopes = {
              {
                client_roles = { { name = "aaa", client = "ccc" } },
                resource = "/bbb"
              }
            },
            type = "blacklist"
          })

          ngx.var = {
            uri = '/bbb'
          }

          local context = {
            jwt = {
              resource_access = {
                ccc = {
                  roles = { "aaa" }
                }
              }
            },
            service = {
              auth_failed_status = 403,
              error_auth_failed = "auth failed"
            }
          }

          role_check_policy:access(context)
          assert.same(ngx.status, 403)
        end)

        it('when multi roles match the ones in jwt', function()
          local role_check_policy = KeycloakRoleCheckPolicy.new({
            scopes = {
              {
                realm_roles = { { name = "ddd" } },
                client_roles = { { name = "aaa", client = "ccc" } },
                resource = "/bbb"
              }
            },
            type = "blacklist"
          })

          ngx.var = {
            uri = '/bbb'
          }

          local context = {
            jwt = {
              realm_access = {
                roles = {"ddd", "eee"}
              },
              resource_access = {
                ccc = {
                  roles = { "aaa" }
                }
              }
            },
            service = {
              auth_failed_status = 403,
              error_auth_failed = "auth failed"
            }
          }

          role_check_policy:access(context)
          assert.same(ngx.status, 403)
        end)

        it('when client role using wildcard matches the one in jwt', function()
          local role_check_policy = KeycloakRoleCheckPolicy.new({
            scopes = {
              {
                client_roles = { { name = "aaa", client = "client" } },
                resource = "/{wildcard}/client"
              }
            },
            type = "blacklist"
          })

          ngx.var = {
            uri = '/group-10/client/resources'
          }

          local context = {
            jwt = {
              resource_access = {
                client = {
                  roles = { "aaa", "other_role" }
                }
              }
            },
            service = {
              auth_failed_status = 403,
              error_auth_failed = "auth failed"
            }
          }

          role_check_policy:access(context)
          assert.same(ngx.status, 403)
        end)

        it('when roles of one of multi scopes match the ones in jwt', function()
          local role_check_policy = KeycloakRoleCheckPolicy.new({
            scopes = {
              {
                client_roles = { { name = "role_of_known_client", client = "known_client" } },
                resource = "/not-accessed/"
              },
              {
                realm_roles = { { name = "unknown_role" } },
                client_roles = { { name = "role_of_known_client", client = "unknown_client" } },
                resource = "/account-a"
              },
              {
                realm_roles = { { name = "known_role" } },
                resource = "/account-a"
              },
              {
                realm_roles = { { name = "unknown_role" } },
                resource = "/group-{wildcard}/account-b"
              },
              {
                client_roles = { { name = "role_of_known_client", client = "known_client" } },
                resource = "/group-{wildcard}/account-b"
              }
            },
            type = "blacklist"
          })

          local context = {
            jwt = {
              realm_access = {
                roles = { "known_role" }
              },
              resource_access = {
                known_client = {
                  roles = { "role_of_known_client" }
                }
              }
            },
            service = {
              auth_failed_status = 403,
              error_auth_failed = "auth failed"
            }
          }

          ngx.var = {
            uri = '/account-a'
          }

          role_check_policy:access(context)
          assert.same(ngx.status, 403)

          ngx.var = {
            uri = '/group-a/account-b'
          }

          role_check_policy:access(context)
          assert.same(ngx.status, 403)
        end)
      end)

      describe('check succeeds', function()
        local role_check_policy
        local context

        before_each(function()
          role_check_policy = KeycloakRoleCheckPolicy.new({
            scopes = {
              {
                client_roles = { { name = "role_of_known_client", client = "known_client" } },
                resource = "/match"
              },
              {
                client_roles = { { name = "role_of_known_client", client = "unknown_client" } },
                resource = "/no-role-resource"
              },
              {
                realm_roles = { { name = "known_role" }, { name = "unknown_role" } },
                resource = "/not-enough-roles-resource"
              },
            },
            type = "blacklist"
          })

          context = {
            jwt = {
              realm_access = {
                roles = { "known_role" }
              },
              resource_access = {
                known_client = {
                  roles = { "role_of_known_client" }
                }
              }
            },
            service = {
              auth_failed_status = 403,
              error_auth_failed = "auth failed"
            }
          }
        end)

        it('when resource does not match the uri', function()
          ngx.var = {
            uri = '/not-match'
          }

          role_check_policy:access(context)
          assert.not_same(ngx.status, 403)
        end)

        it('when there is not the matched role in jwt', function()
          ngx.var = {
            uri = '/no-role-resource'
          }

          role_check_policy:access(context)
          assert.not_same(ngx.status, 403)
        end)

        it('when there are not enough roles in jwt', function()
          ngx.var = {
            uri = '/not-enough-roles-resource'
          }

          role_check_policy:access(context)
          assert.not_same(ngx.status, 403)
        end)
      end)

      describe("validate method roles", function()

        before_each(function()
          ngx.var = {
            uri = '/foo'
          }
        end)

        local context = {
          jwt = {
            realm_access = {
              roles = { "known_role" }
            },
            resource_access = {
              known_client = {
                roles = { "role_of_known_client" }
              }
            }
          },
          service = {
            auth_failed_status = 403,
            error_auth_failed = "auth failed"
          }
        }

        it("Validates that an empty array still make a default any method", function()
          local role_check_policy = KeycloakRoleCheckPolicy.new({
            scopes = {{
                client_roles = { { name = "role_of_known_client", client = "known_client" } },
                resource = "/foo",
                methods = {}
              }}})
          role_check_policy:access(context)
          assert.same(ngx.status, nil)
        end)

        it("when jwt role matches and one method also match", function()
          local role_check_policy = KeycloakRoleCheckPolicy.new({
            scopes = {{
                client_roles = { { name = "role_of_known_client", client = "known_client" } },
                resource = "/foo",
                methods = {"GET", "POST", "PUT"}
              }},
            type = "whitelist"})

          role_check_policy:access(context)
          assert.same(ngx.status, nil)
        end)

        it("when jwt role matches and one method also match with blacklist mode", function()
          local role_check_policy = KeycloakRoleCheckPolicy.new({
            scopes = {{
                client_roles = { { name = "role_of_known_client", client = "known_client" } },
                resource = "/foo",
                methods = {"GET", "POST", "PUT"}
              }},
            type = "blacklist"})

          role_check_policy:access(context)
          assert.same(ngx.status, 403)
        end)

        it("when jwt role matches and no methods matches", function()
          local role_check_policy = KeycloakRoleCheckPolicy.new({
            scopes = {{
                client_roles = { { name = "role_of_known_client", client = "known_client" } },
                resource = "/foo",
                methods = {"POST", "PUT"}
              }},
            type = "whitelist"})
            role_check_policy:access(context)
          assert.same(ngx.status, 403)
        end)

        it("when jwt role matches and no methods matches with blacklist mode", function()
          local role_check_policy = KeycloakRoleCheckPolicy.new({
            scopes = {{
                client_roles = { { name = "role_of_known_client", client = "known_client" } },
                resource = "/foo",
                methods = {"POST", "PUT"}
              }},
            type = "blacklist"})
          role_check_policy:access(context)
          assert.same(ngx.status, nil)
        end)

      end)

    end)
  end)
end)
