use lib 't';
use Test::APIcast 'no_plan';

$ENV{TEST_NGINX_REDIS_HOST} ||= $ENV{REDIS_HOST} || "127.0.0.1";
$ENV{TEST_NGINX_REDIS_PORT} ||= $ENV{REDIS_PORT} || 6379;
$ENV{TEST_NGINX_RESOLVER} ||= `grep nameserver /etc/resolv.conf | awk '{print \$2}' | head -1 | tr '\n' ' '`;

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
                      key = {name = "test1", scope = "service", service_name = "service_C"},
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
                      key = {name = "test1", scope = "service", service_name = "service_C"},
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
  resolver $TEST_NGINX_RESOLVER;

  location /transactions/authrep.xml {
    content_by_lua_block { ngx.exit(200) }
  }

  location /flush_redis {
    content_by_lua_block {
      local env = require('resty.env')
      local redis_host = "$TEST_NGINX_REDIS_HOST" or '127.0.0.1'
      local redis_port = "$TEST_NGINX_REDIS_PORT" or 6379
      local redis = require('resty.redis'):new()
      redis:connect(redis_host, redis_port)
      redis:select(1)
      redis:del("service_C_connections_test1")
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
                      key = {name = "test3"},
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
                      key = {name = "test4"},
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
                      key = {name = "test4"},
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
  resolver $TEST_NGINX_RESOLVER;

  location /flush_redis {
    content_by_lua_block {
      local env = require('resty.env')
      local redis_host = "$TEST_NGINX_REDIS_HOST" or '127.0.0.1'
      local redis_port = "$TEST_NGINX_REDIS_PORT" or 6379
      local redis = require('resty.redis'):new()
      redis:connect(redis_host, redis_port)
      redis:select(1)
      redis:del("connections_test4")
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
                      key = {name = "test5"},
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
                      key = {name = "test6_1"},
                      rate = 20,
                      burst = 10
                    }
                  },
                  connection_limiters = {
                    {
                      key = {name = "test6_2"},
                      conn = 20,
                      burst = 10,
                      delay = 0.5
                    }
                  },
                  fixed_window_limiters = {
                    {
                      key = {name = "test6_3"},
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
  resolver $TEST_NGINX_RESOLVER;

  location /flush_redis {
    content_by_lua_block {
      local env = require('resty.env')
      local redis_host = "$TEST_NGINX_REDIS_HOST" or '127.0.0.1'
      local redis_port = "$TEST_NGINX_REDIS_PORT" or 6379
      local redis = require('resty.redis'):new()
      redis:connect(redis_host, redis_port)
      redis:select(1)
      redis:del("leaky_bucket_test6_1", "connections_test6_2", "fixed_window_test6_3")
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
                      key = {name = "test7"},
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
                      key = {name = "test7"},
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
  resolver $TEST_NGINX_RESOLVER;

  location /flush_redis {
    content_by_lua_block {
      local env = require('resty.env')
      local redis_host = "$TEST_NGINX_REDIS_HOST" or '127.0.0.1'
      local redis_port = "$TEST_NGINX_REDIS_PORT" or 6379
      local redis = require('resty.redis'):new()
      redis:connect(redis_host, redis_port)
      redis:select(1)
      redis:del("connections_test7")
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
                      key = {name = "test8"},
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
  resolver $TEST_NGINX_RESOLVER;

  location /flush_redis {
    content_by_lua_block {
      local env = require('resty.env')
      local redis_host = "$TEST_NGINX_REDIS_HOST" or '127.0.0.1'
      local redis_port = "$TEST_NGINX_REDIS_PORT" or 6379
      local redis = require('resty.redis'):new()
      redis:connect(redis_host, redis_port)
      redis:select(1)
      redis:del("leaky_bucket_test8")
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
  resolver $TEST_NGINX_RESOLVER;

  location /flush_redis {
    content_by_lua_block {
      local env = require('resty.env')
      local redis_host = "$TEST_NGINX_REDIS_HOST" or '127.0.0.1'
      local redis_port = "$TEST_NGINX_REDIS_PORT" or 6379
      local redis = require('resty.redis'):new()
      redis:connect(redis_host, redis_port)
      redis:select(1)
      redis:del("fixed_window_test9")
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
                      key = {name = "test10"},
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
                      key = {name = "test10"},
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
  resolver $TEST_NGINX_RESOLVER;

  location /transactions/authrep.xml {
    content_by_lua_block { ngx.exit(200) }
  }

  location /flush_redis {
    content_by_lua_block {
      local env = require('resty.env')
      local redis_host = "$TEST_NGINX_REDIS_HOST" or '127.0.0.1'
      local redis_port = "$TEST_NGINX_REDIS_PORT" or 6379
      local redis = require('resty.redis'):new()
      redis:connect(redis_host, redis_port)
      redis:select(1)
      redis:del("connections_test10")
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
                      key = {name = "test11"},
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
  resolver $TEST_NGINX_RESOLVER;

  location /transactions/authrep.xml {
    content_by_lua_block { ngx.exit(200) }
  }

  location /flush_redis {
    content_by_lua_block {
      local env = require('resty.env')
      local redis_host = "$TEST_NGINX_REDIS_HOST" or '127.0.0.1'
      local redis_port = "$TEST_NGINX_REDIS_PORT" or 6379
      local redis = require('resty.redis'):new()
      redis:connect(redis_host, redis_port)
      redis:select(1)
      redis:del("leaky_bucket_test11")
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
                      key = {name = "test12"},
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
                      key = {name = "test12"},
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
                      key = {name = "test13"},
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
                      key = {name = "test14"},
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
                      key = {name = "test15"},
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
                      key = {name = "test15"},
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
                      key = {name = "test16"},
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
