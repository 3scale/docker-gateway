local KeycloakRoleCheckPolicy = require('apicast.policy.keycloak_role_check')

describe('Keycloak Role check policy', function()

  before_each(function()
    ngx.header = {}
  end)

  describe('.access', function()
    describe('whitelist', function()
      describe('check succeeds', function()
        it('realm role', function()
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

        it('client role', function()
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

        it('liquid', function()
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

        it('multi roles in policy', function()
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

        it('wildcard', function()
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

        it('multi roles', function()
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

        it('not match the uri', function()
          ngx.var = {
            uri = '/not-match'
          }

          role_check_policy:access(context)
          assert.same(ngx.status, 403)
        end)

        it('no role', function()
          ngx.var = {
            uri = '/no-role-resource'
          }

          role_check_policy:access(context)
          assert.same(ngx.status, 403)
        end)

        it('not enough roles', function()
          ngx.var = {
            uri = '/not-enough-roles-resource'
          }

          role_check_policy:access(context)
          assert.same(ngx.status, 403)
        end)

        it('no jwt', function()
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

    describe('blacklist', function()
      describe('check fails', function()
        it('realm role', function()
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

        it('client role', function()
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

        it('multi roles in policy', function()
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

        it('wildcard', function()
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

        it('multi roles', function()
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

        it('not match the uri', function()
          ngx.var = {
            uri = '/not-match'
          }

          role_check_policy:access(context)
          assert.not_same(ngx.status, 403)
        end)

        it('no role', function()
          ngx.var = {
            uri = '/no-role-resource'
          }

          role_check_policy:access(context)
          assert.not_same(ngx.status, 403)
        end)

        it('not enough roles', function()
          ngx.var = {
            uri = '/not-enough-roles-resource'
          }

          role_check_policy:access(context)
          assert.not_same(ngx.status, 403)
        end)
      end)
    end)
  end)
end)
