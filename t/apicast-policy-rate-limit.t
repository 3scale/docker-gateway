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
                  limiters = {
                    {
                      name = "connections",
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
                  limiters = {
                    {
                      name = "connections",
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
      redis:del("42_connections_test1", "42_connections_test1_seed")
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
                  limiters = {
                    {
                      name = "connections",
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
                  limiters = {
                    {
                      name = "connections",
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
      redis:del("42_connections_test2", "42_connections_test2_seed")
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
                  limiters = {
                    {
                      name = "connections",
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
                  limiters = {
                    {
                      name = "connections",
                      key = {name = "test4", scope = "global"},
                      conn = 1,
                      burst = 0,
                      delay = 2
                    }
                  },
                  redis_url = "redis://$TEST_NGINX_REDIS_HOST:$TEST_NGINX_REDIS_PORT/1",
                  error_settings = {
                    {type = "limits_exceeded", error_handling = "log"}
                  }
                }
              },
              {
                name = "apicast.policy.rate_limit",
                configuration = {
                  limiters = {
                    {
                      name = "connections",
                      key = {name = "test4", scope = "global"},
                      conn = 1,
                      burst = 0,
                      delay = 2
                    }
                  },
                  redis_url = "redis://$TEST_NGINX_REDIS_HOST:$TEST_NGINX_REDIS_PORT/1",
                  error_settings = {
                    {type = "limits_exceeded", error_handling = "log"}
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
  resolver $TEST_NGINX_RESOLVER;

  location /flush_redis {
    content_by_lua_block {
      local env = require('resty.env')
      local redis_host = "$TEST_NGINX_REDIS_HOST" or '127.0.0.1'
      local redis_port = "$TEST_NGINX_REDIS_PORT" or 6379
      local redis = require('resty.redis'):new()
      redis:connect(redis_host, redis_port)
      redis:select(1)
      redis:del("connections_test4", "connections_test4_seed")
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
                  limiters = {
                    {
                      name = "connections",
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
                  limiters = {
                    {
                      name = "leaky_bucket",
                      key = {name = "test6_1", scope = "global"},
                      rate = 20,
                      burst = 10
                    },
                    {
                      name = "connections",
                      key = {name = "test6_2", scope = "global"},
                      conn = 20,
                      burst = 10,
                      delay = 0.5
                    },
                    {
                      name = "fixed_window",
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
  resolver $TEST_NGINX_RESOLVER;

  location /flush_redis {
    content_by_lua_block {
      local env = require('resty.env')
      local redis_host = "$TEST_NGINX_REDIS_HOST" or '127.0.0.1'
      local redis_port = "$TEST_NGINX_REDIS_PORT" or 6379
      local redis = require('resty.redis'):new()
      redis:connect(redis_host, redis_port)
      redis:select(1)
      redis:del("leaky_bucket_test6_1", "connections_test6_2", "fixed_window_test6_3", "fixed_window_test6_3_count", "fixed_window_test6_3_window")
      redis:del("leaky_bucket_test6_1_seed", "connections_test6_2_seed", "fixed_window_test6_3_seed")
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
                  limiters = {
                    {
                      name = "connections",
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
                  limiters = {
                    {
                      name = "connections",
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
  resolver $TEST_NGINX_RESOLVER;

  location /flush_redis {
    content_by_lua_block {
      local env = require('resty.env')
      local redis_host = "$TEST_NGINX_REDIS_HOST" or '127.0.0.1'
      local redis_port = "$TEST_NGINX_REDIS_PORT" or 6379
      local redis = require('resty.redis'):new()
      redis:connect(redis_host, redis_port)
      redis:select(1)
      redis:del("connections_test7", "connections_test7_seed")
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
                  limiters = {
                    {
                      name = "leaky_bucket",
                      key = {name = "test8", scope = "global"},
                      rate = 1,
                      burst = 0
                    }
                  },
                  redis_url = "redis://$TEST_NGINX_REDIS_HOST:$TEST_NGINX_REDIS_PORT/1",
                  error_settings = {
                    {type = "limits_exceeded", status_code = 503}
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
  resolver $TEST_NGINX_RESOLVER;

  location /flush_redis {
    content_by_lua_block {
      local env = require('resty.env')
      local redis_host = "$TEST_NGINX_REDIS_HOST" or '127.0.0.1'
      local redis_port = "$TEST_NGINX_REDIS_PORT" or 6379
      local redis = require('resty.redis'):new()
      redis:connect(redis_host, redis_port)
      redis:select(1)
      redis:del("leaky_bucket_test8", "leaky_bucket_test8_seed")
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
                  limiters = {
                    {
                      name = "fixed_window",
                      key = {name = "test9", scope = "global"},
                      count = 1,
                      window = 10
                    }
                  },
                  redis_url = "redis://$TEST_NGINX_REDIS_HOST:$TEST_NGINX_REDIS_PORT/1",
                  error_settings = {
                    {type = "limits_exceeded", status_code = 429}
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
  resolver $TEST_NGINX_RESOLVER;

  location /flush_redis {
    content_by_lua_block {
      local env = require('resty.env')
      local redis_host = "$TEST_NGINX_REDIS_HOST" or '127.0.0.1'
      local redis_port = "$TEST_NGINX_REDIS_PORT" or 6379
      local redis = require('resty.redis'):new()
      redis:connect(redis_host, redis_port)
      redis:select(1)
      redis:del("fixed_window_test9", "fixed_window_test9_count", "fixed_window_test9_window", "fixed_window_test9_seed")
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
                  limiters = {
                    {
                      name = "connections",
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
                  limiters = {
                    {
                      name = "connections",
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
      redis:del("connections_test10", "connections_test10_seed")
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
                  limiters = {
                    {
                      name = "leaky_bucket",
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
      redis:del("leaky_bucket_test11", "leaky_bucket_test11_seed")
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
                  limiters = {
                    {
                      name = "connections",
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
                  limiters = {
                    {
                      name = "connections",
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
                  limiters = {
                    {
                      name = "leaky_bucket",
                      key = {name = "test13", scope = "global"},
                      rate = 1,
                      burst = 0
                    }
                  },
                  error_settings = {
                    {type = "limits_exceeded", error_handling = "exit"}
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
                  limiters = {
                    {
                      name = "fixed_window",
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
                  limiters = {
                    {
                      name = "connections",
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
                  limiters = {
                    {
                      name = "connections",
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
                  limiters = {
                    {
                      name = "leaky_bucket",
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
