local KeycloakScopeCheckPolicy = require('apicast.policy.keycloak_scope_check')

describe('Keycloak Scope check policy', function()
  local ngx_exit_spy
  local ngx_say_spy

  before_each(function()
    ngx_exit_spy = spy.on(ngx, 'exit')
    ngx_say_spy = spy.on(ngx, 'say')
  end)

  describe('.access', function()
    describe('whitelist', function()
      describe('check succeeds', function()
        it('realm role', function()
          local scope_check_policy = KeycloakScopeCheckPolicy.new({
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

          scope_check_policy:access(context)
          assert.spy(ngx_say_spy).was_not_called()
        end)

        it('client role', function()
          local scope_check_policy = KeycloakScopeCheckPolicy.new({
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

          scope_check_policy:access(context)
          assert.spy(ngx_say_spy).was_not_called()
        end)

        it('multi roles in policy', function()
          local scope_check_policy = KeycloakScopeCheckPolicy.new({
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

          scope_check_policy:access(context)
          assert.spy(ngx_say_spy).was_not_called()
        end)

        it('wildcard', function()
          local scope_check_policy = KeycloakScopeCheckPolicy.new({
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

          scope_check_policy:access(context)
          assert.spy(ngx_say_spy).was_not_called()
        end)

        it('multi scopes', function()
          local scope_check_policy = KeycloakScopeCheckPolicy.new({
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

          scope_check_policy:access(context)
          assert.spy(ngx_say_spy).was_not_called()

          ngx.var = {
            uri = '/group-a/account-b'
          }

          scope_check_policy:access(context)
          assert.spy(ngx_say_spy).was_not_called()
        end)
      end)

      describe('check fails', function()
        local scope_check_policy
        local context

        before_each(function()
          scope_check_policy = KeycloakScopeCheckPolicy.new({
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

          scope_check_policy:access(context)
          assert.same(ngx.status, 403)
          assert.spy(ngx_exit_spy).was_called_with(403)
          assert.spy(ngx_say_spy).was_called_with("auth failed")
        end)

        it('no role', function()
          ngx.var = {
            uri = '/no-role-resource'
          }

          scope_check_policy:access(context)
          assert.same(ngx.status, 403)
          assert.spy(ngx_exit_spy).was_called_with(403)
          assert.spy(ngx_say_spy).was_called_with("auth failed")
        end)

        it('not enough roles', function()
          ngx.var = {
            uri = '/not-enough-roles-resource'
          }

          scope_check_policy:access(context)
          assert.same(ngx.status, 403)
          assert.spy(ngx_exit_spy).was_called_with(403)
          assert.spy(ngx_say_spy).was_called_with("auth failed")
        end)
      end)
    end)

    describe('blacklist', function()
      describe('check fails', function()
        it('realm role', function()
          local scope_check_policy = KeycloakScopeCheckPolicy.new({
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

          scope_check_policy:access(context)
          assert.same(ngx.status, 403)
          assert.spy(ngx_exit_spy).was_called_with(403)
          assert.spy(ngx_say_spy).was_called_with("auth failed")
        end)

        it('client role', function()
          local scope_check_policy = KeycloakScopeCheckPolicy.new({
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

          scope_check_policy:access(context)
          assert.same(ngx.status, 403)
          assert.spy(ngx_exit_spy).was_called_with(403)
          assert.spy(ngx_say_spy).was_called_with("auth failed")
        end)

        it('multi roles in policy', function()
          local scope_check_policy = KeycloakScopeCheckPolicy.new({
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

          scope_check_policy:access(context)
          assert.same(ngx.status, 403)
          assert.spy(ngx_exit_spy).was_called_with(403)
          assert.spy(ngx_say_spy).was_called_with("auth failed")
        end)

        it('wildcard', function()
          local scope_check_policy = KeycloakScopeCheckPolicy.new({
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

          scope_check_policy:access(context)
          assert.same(ngx.status, 403)
          assert.spy(ngx_exit_spy).was_called_with(403)
          assert.spy(ngx_say_spy).was_called_with("auth failed")
        end)

        it('multi scopes', function()
          local scope_check_policy = KeycloakScopeCheckPolicy.new({
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

          scope_check_policy:access(context)
          assert.same(ngx.status, 403)
          assert.spy(ngx_exit_spy).was_called_with(403)
          assert.spy(ngx_say_spy).was_called_with("auth failed")

          ngx.var = {
            uri = '/group-a/account-b'
          }

          scope_check_policy:access(context)
          assert.same(ngx.status, 403)
          assert.spy(ngx_exit_spy).was_called_with(403)
          assert.spy(ngx_say_spy).was_called_with("auth failed")
        end)
      end)

      describe('check succeeds', function()
        local scope_check_policy
        local context

        before_each(function()
          scope_check_policy = KeycloakScopeCheckPolicy.new({
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

          scope_check_policy:access(context)
          assert.spy(ngx_say_spy).was_not_called()
        end)

        it('no role', function()
          ngx.var = {
            uri = '/no-role-resource'
          }

          scope_check_policy:access(context)
          assert.spy(ngx_say_spy).was_not_called()
        end)

        it('not enough roles', function()
          ngx.var = {
            uri = '/not-enough-roles-resource'
          }

          scope_check_policy:access(context)
          assert.spy(ngx_say_spy).was_not_called()
        end)
      end)
    end)
  end)
end)
