local ScopeCheckPolicy = require('apicast.policy.scope_check')

describe('Scope check policy', function()
  local ngx_exit_spy
  local ngx_say_spy

  setup(function()
    ngx_exit_spy = spy.on(ngx, 'exit')
    ngx_say_spy = spy.on(ngx, 'say')
  end)

  describe('.access', function()
    describe('whitelist', function()
      describe('check succeeds', function()
        it('realm role', function()
          local scope_check_policy = ScopeCheckPolicy.new({
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

          assert(scope_check_policy:access(context))
        end)

        it('client role', function()
          local scope_check_policy = ScopeCheckPolicy.new({
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

          assert(scope_check_policy:access(context))
        end)

        it('multi roles in policy', function()
          local scope_check_policy = ScopeCheckPolicy.new({
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

          assert(scope_check_policy:access(context))
        end)

        it('wildcard', function()
          local scope_check_policy = ScopeCheckPolicy.new({
            scopes = {
              {
                client_roles = { { name = "aaa", client = "ccc" } },
                resource = "/bbb/{wildcard}"
              }
            }
          })

          ngx.var = {
            uri = '/bbb/ddd'
          }

          local context = {
            jwt = {
              resource_access = {
                ccc = {
                  roles = { "aaa", "eee" }
                }
              }
            }
          }

          assert(scope_check_policy:access(context))
        end)

        it('multi scopes', function()
          local scope_check_policy = ScopeCheckPolicy.new({
            scopes = {
              {
                client_roles = { { name = "aaa", client = "ccc" } },
                resource = "/bbb/{wildcard}"
              },
              {
                realm_roles = { { name = "rrr" } },
                client_roles = { { name = "fff", client = "hhh" } },
                resource = "/eee{wildcard}"
              },
              {
                realm_roles = { { name = "ddd" } },
                resource = "/eeeyyy{wildcard}"
              },
              {
                realm_roles = { { name = "rrr" } },
                resource = "/{wildcard}ggg"
              },
              {
                client_roles = { { name = "fff", client = "hhh" } },
                resource = "/z{wildcard}ggg"
              }
            }
          })

          local context = {
            jwt = {
              realm_access = {
                roles = { "ddd" }
              },
              resource_access = {
                hhh = {
                  roles = { "fff" }
                }
              }
            },
            service = {
              auth_failed_status = 403,
              error_auth_failed = "auth failed"
            }
          }

          ngx.var = {
            uri = '/eeeyyyy'
          }

          assert(scope_check_policy:access(context))

          ngx.var = {
            uri = '/zzzggg'
          }

          assert(scope_check_policy:access(context))
        end)
      end)

      describe('check fails', function()
        local scope_check_policy
        local context

        before_each(function()
          scope_check_policy = ScopeCheckPolicy.new({
            scopes = {
              {
                client_roles = { { name = "aaa", client = "ccc" } },
                resource = "/bbb/{wildcard}"
              },
              {
                realm_roles = { { name = "ddd" }, { name = "uuu" } },
                resource = "/eee{wildcard}"
              },
              {
                client_roles = { { name = "fff", client = "hhh" } },
                resource = "/{wildcard}ggg"
              },
            }
          })

          context = {
            jwt = {
              realm_access = {
                roles = { "ddd" }
              },
              resource_access = {
                hhh = {
                  roles = { "fff" }
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
            uri = '/zzz/gggaaa'
          }

          scope_check_policy:access(context)
          assert.same(ngx.status, 403)
          assert.spy(ngx_exit_spy).was_called_with(403)
          assert.spy(ngx_say_spy).was_called_with("auth failed")
        end)

        it('no role', function()
          ngx.var = {
            uri = '/bbb/xxx'
          }

          scope_check_policy:access(context)
          assert.same(ngx.status, 403)
          assert.spy(ngx_exit_spy).was_called_with(403)
          assert.spy(ngx_say_spy).was_called_with("auth failed")
        end)

        it('not enough roles', function()
          ngx.var = {
            uri = '/eeeaaa'
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
          local scope_check_policy = ScopeCheckPolicy.new({
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
          local scope_check_policy = ScopeCheckPolicy.new({
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
          local scope_check_policy = ScopeCheckPolicy.new({
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
          local scope_check_policy = ScopeCheckPolicy.new({
            scopes = {
              {
                client_roles = { { name = "aaa", client = "ccc" } },
                resource = "/bbb/{wildcard}"
              }
            },
            type = "blacklist"
          })

          ngx.var = {
            uri = '/bbb/ddd'
          }

          local context = {
            jwt = {
              resource_access = {
                ccc = {
                  roles = { "aaa", "eee" }
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
          local scope_check_policy = ScopeCheckPolicy.new({
            scopes = {
              {
                client_roles = { { name = "aaa", client = "ccc" } },
                resource = "/bbb/{wildcard}"
              },
              {
                realm_roles = { { name = "rrr" } },
                client_roles = { { name = "fff", client = "hhh" } },
                resource = "/eee{wildcard}"
              },
              {
                realm_roles = { { name = "ddd" } },
                resource = "/eeeyyy{wildcard}"
              },
              {
                realm_roles = { { name = "rrr" } },
                resource = "/{wildcard}ggg"
              },
              {
                client_roles = { { name = "fff", client = "hhh" } },
                resource = "/z{wildcard}ggg"
              }
            },
            type = "blacklist"
          })

          local context = {
            jwt = {
              realm_access = {
                roles = { "ddd" }
              },
              resource_access = {
                hhh = {
                  roles = { "fff" }
                }
              }
            },
            service = {
              auth_failed_status = 403,
              error_auth_failed = "auth failed"
            }
          }

          ngx.var = {
            uri = '/eeeyyyy'
          }

          scope_check_policy:access(context)
          assert.same(ngx.status, 403)
          assert.spy(ngx_exit_spy).was_called_with(403)
          assert.spy(ngx_say_spy).was_called_with("auth failed")

          ngx.var = {
            uri = '/zzzggg'
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
          scope_check_policy = ScopeCheckPolicy.new({
            scopes = {
              {
                client_roles = { { name = "aaa", client = "ccc" } },
                resource = "/bbb/{wildcard}"
              },
              {
                realm_roles = { { name = "ddd" }, { name = "uuu" } },
                resource = "/eee{wildcard}"
              },
              {
                client_roles = { { name = "fff", client = "hhh" } },
                resource = "/{wildcard}ggg"
              },
            },
            type = "blacklist"
          })

          context = {
            jwt = {
              realm_access = {
                roles = { "ddd" }
              },
              resource_access = {
                hhh = {
                  roles = { "fff" }
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
            uri = '/zzz/gggaaa'
          }

          assert(scope_check_policy:access(context))
        end)

        it('no role', function()
          ngx.var = {
            uri = '/bbb/xxx'
          }

          assert(scope_check_policy:access(context))
        end)

        it('not enough roles', function()
          ngx.var = {
            uri = '/eeeaaa'
          }

          assert(scope_check_policy:access(context))
        end)
      end)
    end)
  end)
end)
