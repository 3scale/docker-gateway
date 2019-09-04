use lib 't';
use Test::APIcast 'no_plan';
use Cwd qw(abs_path);

$ENV{TEST_NGINX_LUA_PATH} = "$Test::APIcast::spec/?.lua;$ENV{TEST_NGINX_LUA_PATH}";
$ENV{TEST_NGINX_REDIS_HOST} ||= $ENV{REDIS_HOST} || "127.0.0.1";
$ENV{TEST_NGINX_REDIS_PORT} ||= $ENV{REDIS_PORT} || 6379;
$ENV{BACKEND_ENDPOINT_OVERRIDE} ||= "http://127.0.0.1:$Test::Nginx::Util::ServerPortForClient/backend";

our $rsa = `cat t/fixtures/rsa.pem`;
env_to_nginx('BACKEND_ENDPOINT_OVERRIDE');

repeat_each(1);
run_tests();

__DATA__

=== TEST 1: Delay (conn) service scope.
Return 200 code.
--- http_config
  include $TEST_NGINX_UPSTREAM_CONFIG;
  lua_package_path "$TEST_NGINX_LUA_PATH";

  init_by_lua_block {
    require "resty.core"
    ngx.shared.limiter:flush_all()
    require('apicast.configuration_loader').mock({
      services = {
        {
          id = 42,
          proxy = {
            policy_chain = {
              {
                name = "apicast.policy.rate_limit",
                configuration = {
                  connection_limiters = {
                    {
                      key = {name = "test1", scope = "service"},
                      conn = 1,
                      burst = 1,
                      delay = 2
                    }
                  },
                  redis_url = "redis://$TEST_NGINX_REDIS_HOST:$TEST_NGINX_REDIS_PORT/1"
                }
              },
              {
                name = "apicast.policy.rate_limit",
                configuration = {
                  connection_limiters = {
                    {
                      key = {name = "test1", scope = "service"},
                      conn = 1,
                      burst = 1,
                      delay = 2
                    }
                  },
                  redis_url = "redis://$TEST_NGINX_REDIS_HOST:$TEST_NGINX_REDIS_PORT/1"
                }
              }
            }
          }
        }
      }
    })
  }
  lua_shared_dict limiter 1m;

--- config
  include $TEST_NGINX_APICAST_CONFIG;

  location /transactions/authrep.xml {
    content_by_lua_block { ngx.exit(200) }
  }

  location /flush_redis {
    content_by_lua_block {
      local redis = require('apicast.threescale_utils').connect_redis({
         host = "$TEST_NGINX_REDIS_HOST",
         port = "$TEST_NGINX_REDIS_PORT",
         db=1})
      redis:del('42_connections_test1')
    }
  }

--- pipelined_requests eval
["GET /flush_redis","GET /"]
--- error_code eval
[200, 200]

=== TEST 2: Delay (conn) default service scope.
Return 200 code.
--- http_config
  include $TEST_NGINX_UPSTREAM_CONFIG;
  lua_package_path "$TEST_NGINX_LUA_PATH";

  init_by_lua_block {
    require "resty.core"
    ngx.shared.limiter:flush_all()
    require('apicast.configuration_loader').mock({
      services = {
        {
          id = 42,
          proxy = {
            policy_chain = {
              {
                name = "apicast.policy.rate_limit",
                configuration = {
                  connection_limiters = {
                    {
                      key = {name = "test2"},
                      conn = 1,
                      burst = 1,
                      delay = 2
                    }
                  },
                  redis_url = "redis://$TEST_NGINX_REDIS_HOST:$TEST_NGINX_REDIS_PORT/1"
                }
              },
              {
                name = "apicast.policy.rate_limit",
                configuration = {
                  connection_limiters = {
                    {
                      key = {name = "test2"},
                      conn = 1,
                      burst = 1,
                      delay = 2
                    }
                  },
                  redis_url = "redis://$TEST_NGINX_REDIS_HOST:$TEST_NGINX_REDIS_PORT/1"
                }
              }
            }
          }
        }
      }
    })
  }
  lua_shared_dict limiter 1m;

--- config
  include $TEST_NGINX_APICAST_CONFIG;

  location /transactions/authrep.xml {
    content_by_lua_block { ngx.exit(200) }
  }

  location /flush_redis {
    content_by_lua_block {
      local redis = require('apicast.threescale_utils').connect_redis({
         host = "$TEST_NGINX_REDIS_HOST",
         port = "$TEST_NGINX_REDIS_PORT",
         db=1})
      redis:del('42_connections_test2')
    }
  }

--- pipelined_requests eval
["GET /flush_redis","GET /"]
--- error_code eval
[200, 200]

=== TEST 3: Invalid redis url.
Return 500 code.
--- http_config
  include $TEST_NGINX_UPSTREAM_CONFIG;
  lua_package_path "$TEST_NGINX_LUA_PATH";

  init_by_lua_block {
    require "resty.core"
    ngx.shared.limiter:flush_all()
    require('apicast.configuration_loader').mock({
      services = {
        {
          id = 42,
          proxy = {
            policy_chain = {
              {
                name = "apicast.policy.rate_limit",
                configuration = {
                  connection_limiters = {
                    {
                      key = {name = "test3", scope = "global"},
                      conn = 20,
                      burst = 10,
                      delay = 0.5
                    }
                  },
                  redis_url = "redis://invalidhost:$TEST_NGINX_REDIS_PORT/1"
                }
              }
            }
          }
        }
      }
    })
  }
  lua_shared_dict limiter 1m;

--- config
  include $TEST_NGINX_APICAST_CONFIG;

--- request
GET /
--- error_code: 500

=== TEST 4: Rejected (conn) logging only.
Return 200 code.
--- http_config
  include $TEST_NGINX_UPSTREAM_CONFIG;
  lua_package_path "$TEST_NGINX_LUA_PATH";

  init_by_lua_block {
    require "resty.core"
    ngx.shared.limiter:flush_all()
    require('apicast.configuration_loader').mock({
      services = {
        {
          id = 42,
          proxy = {
            policy_chain = {
              {
                name = "apicast.policy.rate_limit",
                configuration = {
                  connection_limiters = {
                    {
                      key = {name = "test4", scope = "global"},
                      conn = 1,
                      burst = 0,
                      delay = 2
                    }
                  },
                  redis_url = "redis://$TEST_NGINX_REDIS_HOST:$TEST_NGINX_REDIS_PORT/1",
                  limits_exceeded_error  = { error_handling = "log" }
                }
              },
              {
                name = "apicast.policy.rate_limit",
                configuration = {
                  connection_limiters = {
                    {
                      key = {name = "test4", scope = "global"},
                      conn = 1,
                      burst = 0,
                      delay = 2
                    }
                  },
                  redis_url = "redis://$TEST_NGINX_REDIS_HOST:$TEST_NGINX_REDIS_PORT/1",
                  limits_exceeded_error  = { error_handling = "log" }
                }
              }
            }
          }
        }
      }
    })
  }
  lua_shared_dict limiter 1m;

--- config
  include $TEST_NGINX_APICAST_CONFIG;

  location /flush_redis {
    content_by_lua_block {
      local redis = require('apicast.threescale_utils').connect_redis({
         host = "$TEST_NGINX_REDIS_HOST",
         port = "$TEST_NGINX_REDIS_PORT",
         db=1})
      redis:del('connections_test4')
    }
  }

--- pipelined_requests eval
["GET /flush_redis","GET /"]
--- error_code eval
[200, 200]

=== TEST 5: No redis url.
Return 200 code.
--- http_config
  include $TEST_NGINX_UPSTREAM_CONFIG;
  lua_package_path "$TEST_NGINX_LUA_PATH";

  init_by_lua_block {
    require "resty.core"
    ngx.shared.limiter:flush_all()
    require('apicast.configuration_loader').mock({
      services = {
        {
          id = 42,
          proxy = {
            policy_chain = {
              {
                name = "apicast.policy.rate_limit",
                configuration = {
                  connection_limiters = {
                    {
                      key = {name = "test5", scope = "global"},
                      conn = 20,
                      burst = 10,
                      delay = 0.5
                    }
                  }
                }
              }
            }
          }
        }
      }
    })
  }
  lua_shared_dict limiter 1m;

--- config
  include $TEST_NGINX_APICAST_CONFIG;

--- request
GET /
--- error_code: 200
--- no_error_log
[error]

=== TEST 6: Success with multiple limiters.
Return 200 code.
--- http_config
  include $TEST_NGINX_UPSTREAM_CONFIG;
  lua_package_path "$TEST_NGINX_LUA_PATH";

  init_by_lua_block {
    require "resty.core"
    ngx.shared.limiter:flush_all()
    require('apicast.configuration_loader').mock({
      services = {
        {
          id = 42,
          proxy = {
            policy_chain = {
              {
                name = "apicast.policy.rate_limit",
                configuration = {
                  leaky_bucket_limiters = {
                    {
                      key = {name = "test6_1", scope = "global"},
                      rate = 20,
                      burst = 10
                    }
                  },
                  connection_limiters = {
                    {
                      key = {name = "test6_2", scope = "global"},
                      conn = 20,
                      burst = 10,
                      delay = 0.5
                    }
                  },
                  fixed_window_limiters = {
                    {
                      key = {name = "test6_3", scope = "global"},
                      count = 20,
                      window = 10
                    }
                  },
                  redis_url = "redis://$TEST_NGINX_REDIS_HOST:$TEST_NGINX_REDIS_PORT/1"
                }
              }
            }
          }
        }
      }
    })
  }
  lua_shared_dict limiter 1m;

--- config
  include $TEST_NGINX_APICAST_CONFIG;

  location /flush_redis {
    content_by_lua_block {
      local redis = require('apicast.threescale_utils').connect_redis({
         host = "$TEST_NGINX_REDIS_HOST",
         port = "$TEST_NGINX_REDIS_PORT",
         db=1})
      local redis_key = redis:keys('*_fixed_window_test6_3')[1]
      redis:del('leaky_bucket_test6_1', 'connections_test6_2', redis_key)
    }
  }

--- pipelined_requests eval
["GET /flush_redis","GET /"]
--- error_code eval
[200, 200]
--- no_error_log
[error]
need to delay by

=== TEST 7: Rejected (conn).
Return 429 code.
--- http_config
  include $TEST_NGINX_UPSTREAM_CONFIG;
  lua_package_path "$TEST_NGINX_LUA_PATH";

  init_by_lua_block {
    require "resty.core"
    ngx.shared.limiter:flush_all()
    require('apicast.configuration_loader').mock({
      services = {
        {
          id = 42,
          proxy = {
            policy_chain = {
              {
                name = "apicast.policy.rate_limit",
                configuration = {
                  connection_limiters = {
                    {
                      key = {name = "test7", scope = "global"},
                      conn = 1,
                      burst = 0,
                      delay = 2
                    }
                  },
                  redis_url = "redis://$TEST_NGINX_REDIS_HOST:$TEST_NGINX_REDIS_PORT/1"
                }
              },
              {
                name = "apicast.policy.rate_limit",
                configuration = {
                  connection_limiters = {
                    {
                      key = {name = "test7", scope = "global"},
                      conn = 1,
                      burst = 0,
                      delay = 2
                    }
                  },
                  redis_url = "redis://$TEST_NGINX_REDIS_HOST:$TEST_NGINX_REDIS_PORT/1"
                }
              }
            }
          }
        }
      }
    })
  }
  lua_shared_dict limiter 1m;

--- config
  include $TEST_NGINX_APICAST_CONFIG;

  location /flush_redis {
    content_by_lua_block {
      local redis = require('apicast.threescale_utils').connect_redis({
         host = "$TEST_NGINX_REDIS_HOST",
         port = "$TEST_NGINX_REDIS_PORT",
         db=1})
      redis:del('connections_test7')
    }
  }

--- pipelined_requests eval
["GET /flush_redis","GET /"]
--- error_code eval
[200, 429]
--- no_error_log
[error]

=== TEST 8: Rejected (req).
Return 503 code.
--- http_config
  include $TEST_NGINX_UPSTREAM_CONFIG;
  lua_package_path "$TEST_NGINX_LUA_PATH";

  init_by_lua_block {
    require "resty.core"
    ngx.shared.limiter:flush_all()
    require('apicast.configuration_loader').mock({
      services = {
        {
          id = 42,
          proxy = {
            policy_chain = {
              {
                name = "apicast.policy.rate_limit",
                configuration = {
                  leaky_bucket_limiters = {
                    {
                      key = {name = "test8", name_type = "plain", scope = "global"},
                      rate = 1,
                      burst = 0
                    }
                  },
                  redis_url = "redis://$TEST_NGINX_REDIS_HOST:$TEST_NGINX_REDIS_PORT/1",
                  limits_exceeded_error  = { status_code = 503 }
                }
              }
            }
          }
        }
      }
    })
  }
  lua_shared_dict limiter 1m;

--- config
  include $TEST_NGINX_APICAST_CONFIG;

  location /flush_redis {
    content_by_lua_block {
      local redis = require('apicast.threescale_utils').connect_redis({
         host = "$TEST_NGINX_REDIS_HOST",
         port = "$TEST_NGINX_REDIS_PORT",
         db=1})
      redis:del('leaky_bucket_test8')
    }
  }

--- pipelined_requests eval
["GET /flush_redis","GET /","GET /"]
--- error_code eval
[200, 200, 503]
--- no_error_log
[error]

=== TEST 9: Rejected (count).
Return 429 code.
--- http_config
  include $TEST_NGINX_UPSTREAM_CONFIG;
  lua_package_path "$TEST_NGINX_LUA_PATH";

  init_by_lua_block {
    require "resty.core"
    ngx.shared.limiter:flush_all()
    require('apicast.configuration_loader').mock({
      services = {
        {
          id = 42,
          proxy = {
            policy_chain = {
              {
                name = "apicast.policy.rate_limit",
                configuration = {
                  fixed_window_limiters = {
                    {
                      key = {name = "test9", scope = "global"},
                      count = 1,
                      window = 10
                    }
                  },
                  redis_url = "redis://$TEST_NGINX_REDIS_HOST:$TEST_NGINX_REDIS_PORT/1",
                  limits_exceeded_error = { status_code = 429 }
                }
              }
            }
          }
        }
      }
    })
  }
  lua_shared_dict limiter 1m;

--- config
  include $TEST_NGINX_APICAST_CONFIG;

  location /flush_redis {
    content_by_lua_block {
      local redis = require('apicast.threescale_utils').connect_redis({
         host = "$TEST_NGINX_REDIS_HOST",
         port = "$TEST_NGINX_REDIS_PORT",
         db=1})
      local redis_key = redis:keys('*_fixed_window_test9')[1]
      redis:del(redis_key)
    }
  }

--- pipelined_requests eval
["GET /flush_redis","GET /","GET /"]
--- error_code eval
[200, 200, 429]
--- no_error_log
[error]

=== TEST 10: Delay (conn).
Return 200 code.
--- http_config
  include $TEST_NGINX_UPSTREAM_CONFIG;
  lua_package_path "$TEST_NGINX_LUA_PATH";

  init_by_lua_block {
    require "resty.core"
    ngx.shared.limiter:flush_all()
    require('apicast.configuration_loader').mock({
      services = {
        {
          id = 42,
          proxy = {
            policy_chain = {
              {
                name = "apicast.policy.rate_limit",
                configuration = {
                  connection_limiters = {
                    {
                      key = {name = "test10", scope = "global"},
                      conn = 1,
                      burst = 1,
                      delay = 2
                    }
                  },
                  redis_url = "redis://$TEST_NGINX_REDIS_HOST:$TEST_NGINX_REDIS_PORT/1"
                }
              },
              {
                name = "apicast.policy.rate_limit",
                configuration = {
                  connection_limiters = {
                    {
                      key = {name = "test10", scope = "global"},
                      conn = 1,
                      burst = 1,
                      delay = 2
                    }
                  },
                  redis_url = "redis://$TEST_NGINX_REDIS_HOST:$TEST_NGINX_REDIS_PORT/1"
                }
              }
            }
          }
        }
      }
    })
  }
  lua_shared_dict limiter 1m;

--- config
  include $TEST_NGINX_APICAST_CONFIG;

  location /transactions/authrep.xml {
    content_by_lua_block { ngx.exit(200) }
  }

  location /flush_redis {
    content_by_lua_block {
      local redis = require('apicast.threescale_utils').connect_redis({
         host = "$TEST_NGINX_REDIS_HOST",
         port = "$TEST_NGINX_REDIS_PORT",
         db=1})
      redis:del('connections_test10')
    }
  }

--- pipelined_requests eval
["GET /flush_redis","GET /"]
--- error_code eval
[200, 200]

=== TEST 11: Delay (req).
Return 200 code.
--- http_config
  include $TEST_NGINX_UPSTREAM_CONFIG;
  lua_package_path "$TEST_NGINX_LUA_PATH";

  init_by_lua_block {
    require "resty.core"
    ngx.shared.limiter:flush_all()
    require('apicast.configuration_loader').mock({
      services = {
        {
          id = 42,
          proxy = {
            policy_chain = {
              {
                name = "apicast.policy.rate_limit",
                configuration = {
                  leaky_bucket_limiters = {
                    {
                      key = {name = "test11", scope = "global"},
                      rate = 1,
                      burst = 1
                    }
                  },
                  redis_url = "redis://$TEST_NGINX_REDIS_HOST:$TEST_NGINX_REDIS_PORT/1"
                }
              }
            }
          }
        }
      }
    })
  }
  lua_shared_dict limiter 1m;

--- config
  include $TEST_NGINX_APICAST_CONFIG;

  location /transactions/authrep.xml {
    content_by_lua_block { ngx.exit(200) }
  }

  location /flush_redis {
    content_by_lua_block {
      local redis = require('apicast.threescale_utils').connect_redis({
         host = "$TEST_NGINX_REDIS_HOST",
         port = "$TEST_NGINX_REDIS_PORT",
         db=1})
      redis:del('leaky_bucket_test11')
    }
  }

--- pipelined_requests eval
["GET /flush_redis","GET /","GET /"]
--- error_code eval
[200, 200, 200]

=== TEST 12: Rejected (conn) (no redis).
Return 429 code.
--- http_config
  include $TEST_NGINX_UPSTREAM_CONFIG;
  lua_package_path "$TEST_NGINX_LUA_PATH";

  init_by_lua_block {
    require "resty.core"
    ngx.shared.limiter:flush_all()
    require('apicast.configuration_loader').mock({
      services = {
        {
          id = 42,
          proxy = {
            policy_chain = {
              {
                name = "apicast.policy.rate_limit",
                configuration = {
                  connection_limiters = {
                    {
                      key = {name = "test12", scope = "global"},
                      conn = 1,
                      burst = 0,
                      delay = 2
                    }
                  }
                }
              },
              {
                name = "apicast.policy.rate_limit",
                configuration = {
                  connection_limiters = {
                    {
                      key = {name = "test12", scope = "global"},
                      conn = 1,
                      burst = 0,
                      delay = 2
                    }
                  }
                }
              }
            }
          }
        }
      }
    })
  }
  lua_shared_dict limiter 1m;

--- config
  include $TEST_NGINX_APICAST_CONFIG;

--- request
GET /
--- error_code: 429
--- error_log
Requests over the limit.

=== TEST 13: Rejected (req) (no redis).
Return 429 code.
--- http_config
  include $TEST_NGINX_UPSTREAM_CONFIG;
  lua_package_path "$TEST_NGINX_LUA_PATH";

  init_by_lua_block {
    require "resty.core"
    ngx.shared.limiter:flush_all()
    require('apicast.configuration_loader').mock({
      services = {
        {
          id = 42,
          proxy = {
            policy_chain = {
              {
                name = "apicast.policy.rate_limit",
                configuration = {
                  leaky_bucket_limiters = {
                    {
                      key = {name = "test13", scope = "global"},
                      rate = 1,
                      burst = 0
                    }
                  },
                  limits_exceeded_error = { error_handling = "exit" }
                }
              }
            }
          }
        }
      }
    })
  }
  lua_shared_dict limiter 1m;

--- config
  include $TEST_NGINX_APICAST_CONFIG;

--- pipelined_requests eval
["GET /","GET /"]
--- error_code eval
[200, 429]

=== TEST 14: Rejected (count) (no redis).
Return 429 code.
--- http_config
  include $TEST_NGINX_UPSTREAM_CONFIG;
  lua_package_path "$TEST_NGINX_LUA_PATH";

  init_by_lua_block {
    require "resty.core"
    ngx.shared.limiter:flush_all()
    require('apicast.configuration_loader').mock({
      services = {
        {
          id = 42,
          proxy = {
            policy_chain = {
              {
                name = "apicast.policy.rate_limit",
                configuration = {
                  fixed_window_limiters = {
                    {
                      key = {name = "test14", scope = "global"},
                      count = 1,
                      window = 10
                    }
                  }
                }
              }
            }
          }
        }
      }
    })
  }
  lua_shared_dict limiter 1m;

--- config
  include $TEST_NGINX_APICAST_CONFIG;

--- pipelined_requests eval
["GET /","GET /"]
--- error_code eval
[200, 429]

=== TEST 15: Delay (conn) (no redis).
Return 200 code.
--- http_config
  include $TEST_NGINX_UPSTREAM_CONFIG;
  lua_package_path "$TEST_NGINX_LUA_PATH";

  init_by_lua_block {
    require "resty.core"
    ngx.shared.limiter:flush_all()
    require('apicast.configuration_loader').mock({
      services = {
        {
          id = 42,
          proxy = {
            policy_chain = {
              {
                name = "apicast.policy.rate_limit",
                configuration = {
                  connection_limiters = {
                    {
                      key = {name = "test15", scope = "global"},
                      conn = 1,
                      burst = 1,
                      delay = 2
                    }
                  }
                }
              },
              {
                name = "apicast.policy.rate_limit",
                configuration = {
                  connection_limiters = {
                    {
                      key = {name = "test15", scope = "global"},
                      conn = 1,
                      burst = 1,
                      delay = 2
                    }
                  }
                }
              }
            }
          }
        }
      }
    })
  }
  lua_shared_dict limiter 1m;

--- config
  include $TEST_NGINX_APICAST_CONFIG;

  location /transactions/authrep.xml {
    content_by_lua_block { ngx.exit(200) }
  }

--- request
GET /
--- error_code: 200
--- error_log
need to delay by

=== TEST 16: Delay (req) (no redis).
Return 200 code.
--- http_config
  include $TEST_NGINX_UPSTREAM_CONFIG;
  lua_package_path "$TEST_NGINX_LUA_PATH";

  init_by_lua_block {
    require "resty.core"
    ngx.shared.limiter:flush_all()
    require('apicast.configuration_loader').mock({
      services = {
        {
          id = 42,
          proxy = {
            policy_chain = {
              {
                name = "apicast.policy.rate_limit",
                configuration = {
                  leaky_bucket_limiters = {
                    {
                      key = {name = "test16", scope = "global"},
                      rate = 1,
                      burst = 1
                    }
                  }
                }
              }
            }
          }
        }
      }
    })
  }
  lua_shared_dict limiter 1m;

--- config
  include $TEST_NGINX_APICAST_CONFIG;

  location /transactions/authrep.xml {
    content_by_lua_block { ngx.exit(200) }
  }

--- pipelined_requests eval
["GET /","GET /"]
--- error_code eval
[200, 200]

=== TEST 17: Liquid templating (jwt.aud).
Rate Limit policy accesses to the jwt
which the apicast policy stores to the context.
This test uses "jwt.aud" as key name.
This test calls the service 3 times,
and the second call has a different jwt.aud,
so only the third call returns 429.
--- http_config
  include $TEST_NGINX_UPSTREAM_CONFIG;
  lua_package_path "$TEST_NGINX_LUA_PATH";

  init_by_lua_block {
    require "resty.core"
    ngx.shared.limiter:flush_all()
    require('apicast.configuration_loader').mock({
      services = {
        {
          id = 42,
          backend_version = 'oauth',
          backend_authentication_type = 'provider_key',
          backend_authentication_value = 'fookey',
          proxy = {
            authentication_method = 'oidc',
            oidc_issuer_endpoint = 'https://example.com/auth/realms/apicast',
            api_backend = "http://127.0.0.1:$TEST_NGINX_SERVER_PORT/api-backend/",
            proxy_rules = {
              { pattern = '/', http_method = 'GET', metric_system_name = 'hits', delta = 1  }
            },
            policy_chain = {
              {
                name = "apicast.policy.rate_limit",
                configuration = {
                  fixed_window_limiters = {
                    {
                      key = {name = "{{jwt.aud}}", name_type = "liquid", scope = "global"},
                      count = 1,
                      window = 10
                    }
                  },
                  redis_url = "redis://$TEST_NGINX_REDIS_HOST:$TEST_NGINX_REDIS_PORT/1",
                  limits_exceeded_error = { status_code = 429 }
                }
              },
              { name = "apicast.policy.apicast" }
            }
          }
        }
      },
      oidc = {
        {
          issuer = 'https://example.com/auth/realms/apicast',
          config = { id_token_signing_alg_values_supported = { 'RS256' } },
          keys = { somekid = { pem = require('fixtures.rsa').pub } },
        }
      }
    })
  }
  lua_shared_dict limiter 1m;

--- config
  include $TEST_NGINX_APICAST_CONFIG;

  location /flush_redis {
    content_by_lua_block {
      local redis = require('apicast.threescale_utils').connect_redis({
         host = "$TEST_NGINX_REDIS_HOST",
         port = "$TEST_NGINX_REDIS_PORT",
         db=1})
      local redis_key1 = redis:keys('*_fixed_window_test17_1')[1]
      local redis_key2 = redis:keys('*_fixed_window_test17_2')[1]
      redis:del(redis_key1, redis_key2)
    }
  }

  location /api-backend/ {
    content_by_lua_block {
      ngx.exit(200)
    }
  }

  location = /backend/transactions/oauth_authrep.xml {
    content_by_lua_block {
      ngx.exit(200)
    }
  }

--- pipelined_requests eval
["GET /flush_redis","GET /","GET /", "GET /"]
--- more_headers eval
use Crypt::JWT qw(encode_jwt);
my $jwt1 = encode_jwt(payload => {
  aud => 'test17_1',
  sub => 'someone',
  iss => 'https://example.com/auth/realms/apicast',
  exp => time + 3600 }, key => \$::rsa, alg => 'RS256', extra_headers => { kid => 'somekid' });
my $jwt2 = encode_jwt(payload => {
  aud => 'test17_2',
  sub => 'someone',
  iss => 'https://example.com/auth/realms/apicast',
  exp => time + 3600 }, key => \$::rsa, alg => 'RS256', extra_headers => { kid => 'somekid' });
["Authorization: Bearer $jwt1", "Authorization: Bearer $jwt1", "Authorization: Bearer $jwt2", "Authorization: Bearer $jwt1"]
--- error_code eval
[200, 200, 200, 429]
--- no_error_log
[error]

=== TEST 18: Liquid templating (ngx.***).
This test uses "ngx.var.host" and "ngx.var.uri" as key name.
This test calls the service 3 times,
and the second call has a different ngx.var.uri,
so only the third call returns 429.
--- http_config
  include $TEST_NGINX_UPSTREAM_CONFIG;
  lua_package_path "$TEST_NGINX_LUA_PATH";

  init_by_lua_block {
    require "resty.core"
    ngx.shared.limiter:flush_all()
    require('apicast.configuration_loader').mock({
      services = {
        {
          id = 42,
          proxy = {
            policy_chain = {
              {
                name = "apicast.policy.rate_limit",
                configuration = {
                  fixed_window_limiters = {
                    {
                      key = {name = "{{host}}{{uri}}", name_type = "liquid", scope = "global"},
                      count = 1,
                      window = 10
                    }
                  },
                  redis_url = "redis://$TEST_NGINX_REDIS_HOST:$TEST_NGINX_REDIS_PORT/1",
                  limits_exceeded_error = { status_code = 429 }
                }
              }
            }
          }
        }
      }
    })
  }
  lua_shared_dict limiter 1m;

--- config
  include $TEST_NGINX_APICAST_CONFIG;

  location /flush_redis {
    content_by_lua_block {
      local redis = require('apicast.threescale_utils').connect_redis({
         host = "$TEST_NGINX_REDIS_HOST",
         port = "$TEST_NGINX_REDIS_PORT",
         db=1})
      local redis_key1 = redis:keys('*_fixed_window_localhost/test18_1')[1]
      local redis_key2 = redis:keys('*_fixed_window_localhost/test18_2')[1]
      redis:del(redis_key1, redis_key2)
    }
  }

--- pipelined_requests eval
["GET /flush_redis","GET /test18_1","GET /test18_2", "GET /test18_1"]
--- error_code eval
[200, 200, 200, 429]
--- no_error_log
[error]

=== TEST 19: Rejected (count). Using multiple limiters of the same type.
To confirm that multiple limiters of the same type are configurable
and rejected properly.
--- http_config
  include $TEST_NGINX_UPSTREAM_CONFIG;
  lua_package_path "$TEST_NGINX_LUA_PATH";

  init_by_lua_block {
    require "resty.core"
    ngx.shared.limiter:flush_all()
    require('apicast.configuration_loader').mock({
      services = {
        {
          id = 42,
          proxy = {
            policy_chain = {
              {
                name = "apicast.policy.rate_limit",
                configuration = {
                  fixed_window_limiters = {
                    { key = {name = "{{host}}", name_type = "liquid"}, count = 2, window = 10 },
                    { key = {name = "{{uri}}", name_type = "liquid"}, count = 1, window = 10 }
                  },
                  redis_url = "redis://$TEST_NGINX_REDIS_HOST:$TEST_NGINX_REDIS_PORT/1",
                  limits_exceeded_error = { status_code = 429 }
                }
              }
            }
          }
        }
      }
    })
  }
  lua_shared_dict limiter 1m;

--- config
  include $TEST_NGINX_APICAST_CONFIG;

  location /flush_redis {
    content_by_lua_block {
      local redis = require('apicast.threescale_utils').connect_redis({
         host = "$TEST_NGINX_REDIS_HOST",
         port = "$TEST_NGINX_REDIS_PORT",
         db=1})
      redis:flushdb()
    }
  }

--- pipelined_requests eval
["GET /flush_redis","GET /test19_1","GET /test19_2","GET /test19_3"]
--- error_code eval
[200, 200, 200, 429]
--- no_error_log
[error]

=== TEST 20: with conditions
We define a limit of 1 with a false condition, and a limit of 2 with a
condition that's true. We check that the false condition does not apply by
making 3 requests and checking that only the last one is rejected.
--- http_config
  include $TEST_NGINX_UPSTREAM_CONFIG;
  lua_package_path "$TEST_NGINX_LUA_PATH";

  init_by_lua_block {
    require "resty.core"
    ngx.shared.limiter:flush_all()
    require('apicast.configuration_loader').mock({
      services = {
        {
          id = 42,
          proxy = {
            policy_chain = {
              {
                name = "apicast.policy.rate_limit",
                configuration = {
                  fixed_window_limiters = {
                    {
                      key = { name = "test20_key_1" },
                      count = 2,
                      window = 10,
                      condition = {
                        operations = {
                          {
                            left = "{{ uri }}",
                            left_type = "liquid",
                            op = "==",
                            right = "/"
                          }
                        }
                      }
                    },
                    {
                      key = { name = "test20_key_2" },
                      count = 1,
                      window = 10,
                      condition = {
                        operations = {
                          {
                            left = "1",
                            op = "==",
                            right = "2"
                          }
                        }
                      }
                    }
                  },
                  limits_exceeded_error = { status_code = 429 }
                }
              }
            }
          }
        }
      }
    })
  }
  lua_shared_dict limiter 1m;
--- config
  include $TEST_NGINX_APICAST_CONFIG;
--- pipelined_requests eval
["GET /", "GET /", "GET /"]
--- error_code eval
[200, 200, 429]
--- no_error_log
[error]

=== TEST 21: condition with "matches" operation
This test makes 3 requests that match the URL pattern defined in the
limit. The limit is set to 2. Only the third one should fail.
--- http_config
  include $TEST_NGINX_UPSTREAM_CONFIG;
  lua_package_path "$TEST_NGINX_LUA_PATH";

  init_by_lua_block {
    require "resty.core"
    ngx.shared.limiter:flush_all()
    require('apicast.configuration_loader').mock({
      services = {
        {
          id = 42,
          proxy = {
            policy_chain = {
              {
                name = "apicast.policy.rate_limit",
                configuration = {
                  fixed_window_limiters = {
                    {
                      key = { name = "test21_key_1" },
                      count = 2,
                      window = 60,
                      condition = {
                        operations = {
                          {
                            left = "{{ uri }}",
                            left_type = "liquid",
                            op = "matches",
                            right = "/v1/.*/something/.*",
                            right_type = "plain"
                          }
                        }
                      }
                    }
                  },
                  limits_exceeded_error = { status_code = 429 }
                }
              }
            }
          }
        }
      }
    })
  }
  lua_shared_dict limiter 1m;
--- config
  include $TEST_NGINX_APICAST_CONFIG;
--- pipelined_requests eval
["GET /v1/aaa/something/bbb", "GET /v1/ccc/something/ddd", "GET /v1/eee/something/fff"]
--- error_code eval
[200, 200, 429]
--- no_error_log
[error]


=== TEST 22: Window is set to 0 and default is 1.
Return 429 code.
--- http_config
  include $TEST_NGINX_UPSTREAM_CONFIG;
  lua_package_path "$TEST_NGINX_LUA_PATH";

  init_by_lua_block {
    require "resty.core"
    ngx.shared.limiter:flush_all()
    require('apicast.configuration_loader').mock({
      services = {
        {
          id = 42,
          proxy = {
            policy_chain = {
              {
                name = "apicast.policy.rate_limit",
                configuration = {
                  fixed_window_limiters = {
                    {
                      key = {name = "test9", scope = "global"},
                      count = 1,
                      window = 0
                    }
                  },
                  limits_exceeded_error = { status_code = 429 }
                }
              }
            }
          }
        }
      }
    })
  }
  lua_shared_dict limiter 1m;

--- config
  include $TEST_NGINX_APICAST_CONFIG;

--- pipelined_requests eval
["GET /","GET /"]
--- error_code eval
[200, 429]
