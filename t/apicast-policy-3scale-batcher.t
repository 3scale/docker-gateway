use lib 't';
use Test::APIcast 'no_plan';

use Cwd qw(abs_path);

$ENV{TEST_NGINX_LUA_PATH} = "$Test::APIcast::spec/?.lua;$ENV{TEST_NGINX_LUA_PATH}";

our $rsa = `cat t/fixtures/rsa.pem`;

# Can't run twice because of the report batches
repeat_each(1);

run_tests();

__DATA__

=== TEST 1: caches successful authorizations
This test checks that the policy caches successful authorizations. To do that,
we define a backend that makes sure that it's called only once.
--- http_config
include $TEST_NGINX_UPSTREAM_CONFIG;
lua_shared_dict cached_auths 1m;
lua_shared_dict batched_reports 1m;
lua_shared_dict batched_reports_locks 1m;
lua_package_path "$TEST_NGINX_LUA_PATH";

init_by_lua_block {
  require('apicast.configuration_loader').mock({
    services = {
      {
        id = 42,
        backend_version = 1,
        backend_authentication_type = 'service_token',
        backend_authentication_value = 'token-value',
        proxy = {
          backend = { endpoint = "http://127.0.0.1:$TEST_NGINX_SERVER_PORT" },
          api_backend = "http://127.0.0.1:$TEST_NGINX_SERVER_PORT/api-backend/",
          proxy_rules = {
            { pattern = '/', http_method = 'GET', metric_system_name = 'hits', delta = 2 }
          },
          policy_chain = {
            { name = 'apicast.policy.3scale_batcher', configuration = {} },
            { name = 'apicast.policy.apicast' }
          }
        }
      }
    }
  })
}
--- config
  include $TEST_NGINX_APICAST_CONFIG;

  location /transactions/authorize.xml {
    content_by_lua_block {
      local test_counter = ngx.shared.test_counter or 0
      if test_counter == 0 then
        ngx.shared.test_counter = test_counter + 1
        ngx.exit(200)
      else
        ngx.log(ngx.ERR, 'auth should be cached but called backend anyway')
        ngx.exit(502)
      end
    }
  }

  location /api-backend {
     echo 'yay, api backend';
  }
--- request eval
["GET /test?user_key=foo", "GET /foo?user_key=foo"]
--- response_body eval
["yay, api backend\x{0a}", "yay, api backend\x{0a}"]
--- error_code eval
[ 200, 200 ]
--- no_error_log
[error]

=== TEST 2: caches unsuccessful authorizations
This test checks that the policy caches successful authorizations. To do that,
we define a backend that makes sure that it's called only once.
--- http_config
include $TEST_NGINX_UPSTREAM_CONFIG;
lua_shared_dict cached_auths 1m;
lua_shared_dict batched_reports 1m;
lua_shared_dict batched_reports_locks 1m;
lua_package_path "$TEST_NGINX_LUA_PATH";

init_by_lua_block {
  require('apicast.configuration_loader').mock({
    services = {
      {
        id = 42,
        backend_version = 1,
        backend_authentication_type = 'service_token',
        backend_authentication_value = 'token-value',
        proxy = {
          backend = { endpoint = "http://127.0.0.1:$TEST_NGINX_SERVER_PORT" },
          api_backend = "http://127.0.0.1:$TEST_NGINX_SERVER_PORT/api-backend/",
          proxy_rules = {
            { pattern = '/', http_method = 'GET', metric_system_name = 'hits', delta = 2 }
          },
          policy_chain = {
            { name = 'apicast.policy.3scale_batcher', configuration = {} },
            { name = 'apicast.policy.apicast' }
          }
        }
      }
    }
  })
}
--- config
  include $TEST_NGINX_APICAST_CONFIG;

  location /transactions/authorize.xml {
    content_by_lua_block {
      local test_counter = ngx.shared.test_counter or 0
      if test_counter == 0 then
        ngx.shared.test_counter = test_counter + 1
        ngx.header['3scale-rejection-reason'] = 'limits_exceeded'
        ngx.status = 409
        ngx.exit(ngx.HTTP_OK)
      else
        ngx.log(ngx.ERR, 'auth should be cached but called backend anyway')
        ngx.exit(502)
      end
    }
  }

  location /api-backend {
     echo 'yay, api backend';
  }
--- request eval
["GET /test?user_key=foo", "GET /foo?user_key=foo"]
--- response_body eval
["Limits exceeded", "Limits exceeded"]
--- error_code eval
[ 429, 429 ]
--- no_error_log
[error]

=== TEST 3: reports hits correctly
This test is a bit complex. We want to check that reports are sent correctly to
backend. Reports are sent periodically and also when instances of the policy
are garbage collected. In order to capture those reports, we parse them in
the backend endpoint that receives them (/transactions.xml) and aggregate them
in a shared dictionary that we'll check later. At the end of the test, we force
a report to ensure that there are no pending reports, and then, we call an
endpoint defined specifically for this test (/check_reports) that checks
that the values accumulated in that shared dictionary are correct.
--- http_config
include $TEST_NGINX_UPSTREAM_CONFIG;
lua_shared_dict cached_auths 1m;
lua_shared_dict batched_reports 1m;
lua_shared_dict batched_reports_locks 1m;
lua_package_path "$TEST_NGINX_LUA_PATH";
init_by_lua_block {
  require('apicast.configuration_loader').mock({
    services = {
      {
        id = 1,
        backend_version = 1,
        backend_authentication_type = 'service_token',
        backend_authentication_value = 'token-value',
        proxy = {
          hosts = { 'one' },
          backend = { endpoint = "http://127.0.0.1:$TEST_NGINX_SERVER_PORT" },
          api_backend = "http://127.0.0.1:$TEST_NGINX_SERVER_PORT/api-backend/",
          proxy_rules = {
            { pattern = '/', http_method = 'GET', metric_system_name = 'hits', delta = 2 }
          },
          policy_chain = {
            {
              name = 'apicast.policy.3scale_batcher',
              configuration = { batch_report_seconds = 1 }
            },
            { name = 'apicast.policy.apicast' }
          }
        }
      },
      {
        id = 2,
        backend_version = 1,
        backend_authentication_type = 'service_token',
        backend_authentication_value = 'token-value',
        proxy = {
          hosts = { 'two' },
          backend = { endpoint = "http://127.0.0.1:$TEST_NGINX_SERVER_PORT" },
          api_backend = "http://127.0.0.1:$TEST_NGINX_SERVER_PORT/api-backend/",
          proxy_rules = {
            { pattern = '/', http_method = 'GET', metric_system_name = 'hits', delta = 2 }
          },
          policy_chain = {
            {
              name = 'apicast.policy.3scale_batcher',
              configuration = { batch_report_seconds = 1 }
            },
            { name = 'apicast.policy.apicast' }
          }
        }
      }
    }
  })
}
--- config
  include $TEST_NGINX_APICAST_CONFIG;

  location /transactions/authorize.xml {
    content_by_lua_block {
      ngx.exit(200)
    }
  }

  location /api-backend {
     echo 'yay, api backend';
  }

  location /transactions.xml {
    content_by_lua_block {
     ngx.req.read_body()
     local post_args = ngx.req.get_post_args()

      local post_transactions = {}

      -- Parse the reports.
      -- The keys of the post arguments have this format:
      --   1) "transactions[0][user_key]"
      --   2) "transactions[0][usage][hits]"

      for k, v in pairs(post_args) do
        local index = string.match(k, "transactions%[(%d+)%]%[user_key%]")
        if index then
          post_transactions[index] = post_transactions[index] or {}
          post_transactions[index].user_key = v
        else
          local index, metric = string.match(k, "transactions%[(%d+)%]%[usage%]%[(%w+)%]")
          post_transactions[index] = post_transactions[index] or {}
          post_transactions[index].metric = metric
          post_transactions[index].value = v
        end
      end

      local service_id = ngx.req.get_uri_args()['service_id']

      -- Accumulate the reports in a the shared dict ngx.shared.result

      ngx.shared.result = ngx.shared.result or {}
      ngx.shared.result[service_id] = ngx.shared.result[service_id] or {}

      for _, t in pairs(post_transactions) do
        ngx.shared.result[service_id][t.user_key] = ngx.shared.result[service_id][t.user_key] or {}
        ngx.shared.result[service_id][t.user_key][t.metric] = (ngx.shared.result[service_id][t.user_key][t.metric] or 0) + t.value
      end
    }
  }

  location /force_report_to_backend {
    content_by_lua_block {
      local ReportsBatcher = require ('apicast.policy.3scale_batcher.reports_batcher')
      local reporter = require ('apicast.policy.3scale_batcher.reporter')
      local http_ng_resty = require('resty.http_ng.backend.resty')
      local backend_client = require('apicast.backend_client')

      for service = 1,2 do
        local service_id = tostring(service)

        local reports_batcher = ReportsBatcher.new(
          ngx.shared.batched_reports, 'batched_reports_locks')

        local reports = reports_batcher:get_all(service_id)

        local backend = backend_client:new(
          {
            id = service_id,
            backend_authentication_type = 'service_token',
            backend_authentication_value = 'token-value',
            backend = { endpoint = "http://127.0.0.1:$TEST_NGINX_SERVER_PORT" }
          }, http_ng_resty)

        reporter.report(reports, service_id, backend, reports_batcher)
      end
    }
  }

  location /check_reports {
    content_by_lua_block {
      local luassert = require('luassert')

      for service = 1,2 do
        for user_key = 1,5 do
          -- The mapping rule defines a delta of 2 for hits, and we made 10
          -- requests for each {service, user_key}, so all the counters should
          -- be 20.
          local hits = ngx.shared.result[tostring(service)][tostring(user_key)].hits
          luassert.equals(20, hits)
        end
      end
    }
  }

--- request eval
my $res = [];

for(my $i = 0; $i < 20; $i = $i + 1 ) {
  for(my $n = 1; $n <= 5; $n = $n + 1 ) {
    push @$res, "GET /test?user_key=$n";
  }
}

push @$res, "GET /force_report_to_backend";
push @$res, "GET /check_reports";

$res
--- more_headers eval
my $res = [];

for(my $i = 0; $i < 50; $i = $i + 1 ) {
  push @$res, "Host: one";
}

for(my $i = 0; $i < 50; $i = $i + 1 ) {
  push @$res, "Host: two";
}

push @$res, "Host: one";
push @$res, "Host: one";

$res
--- no_error_log
[error]

=== TEST 4: after apicast policy in the chain
We want to check that only the batcher policy is reporting to backend. We know
that the APIcast policy calls "/transactions/authrep.xml" whereas the batcher
calls "/transactions/authorize.xml" and "/transactions.xml", because it
authorizes and reports separately. Therefore, raising an error in
"/transactions/authrep.xml" is enough to detect that the APIcast policy is
calling backend when it's not supposed to.
--- http_config
include $TEST_NGINX_UPSTREAM_CONFIG;
lua_shared_dict cached_auths 1m;
lua_shared_dict batched_reports 1m;
lua_shared_dict batched_reports_locks 1m;
lua_package_path "$TEST_NGINX_LUA_PATH";
init_by_lua_block {
  require('apicast.configuration_loader').mock({
    services = {
      {
        id = 1,
        backend_version = 1,
        backend_authentication_type = 'service_token',
        backend_authentication_value = 'token-value',
        proxy = {
          backend = { endpoint = "http://127.0.0.1:$TEST_NGINX_SERVER_PORT" },
          api_backend = "http://127.0.0.1:$TEST_NGINX_SERVER_PORT/api-backend/",
          proxy_rules = {
            { pattern = '/', http_method = 'GET', metric_system_name = 'hits', delta = 2 }
          },
          policy_chain = {
            { name = 'apicast.policy.apicast' },
            {
              name = 'apicast.policy.3scale_batcher',
              configuration = { batch_report_seconds = 1 }
            }
          }
        }
      }
    }
  })
}
--- config
  include $TEST_NGINX_APICAST_CONFIG;

  location /transactions/authrep.xml {
    content_by_lua_block {
      ngx.log(ngx.ERR, 'APIcast policy called authrep and it was not supposed to!')
    }
  }

  location /transactions/authorize.xml {
    content_by_lua_block {
      ngx.exit(200)
    }
  }

  location /api-backend {
     echo 'yay, api backend';
  }

  location /transactions.xml {
    content_by_lua_block {
      ngx.exit(200)
    }
  }

--- request
GET /test?user_key=uk
--- error_code: 200
--- no_error_log
[error]

=== TEST 5: with caching policy (resilient mode)
The purpose of this test is to test that the 3scale batcher policy works
correctly when combined with the caching one.
In this case, the caching policy is configured as "resilient". We define a
backend that returns 200, and an error in all the rest.
The caching policy will cache the first result and return it while backend is
down.
To make sure that nothing is cached in the 3scale batcher policy, we flush its
auth cache on every request (see rewrite_by_lua_block).
--- http_config
include $TEST_NGINX_UPSTREAM_CONFIG;
lua_shared_dict api_keys 10m;
lua_shared_dict cached_auths 1m;
lua_shared_dict batched_reports 1m;
lua_shared_dict batched_reports_locks 1m;
lua_package_path "$TEST_NGINX_LUA_PATH";

init_by_lua_block {
  require('apicast.configuration_loader').mock({
    services = {
      {
        id = 42,
        backend_version = 1,
        backend_authentication_type = 'service_token',
        backend_authentication_value = 'token-value',
        proxy = {
          backend = { endpoint = "http://127.0.0.1:$TEST_NGINX_SERVER_PORT" },
          api_backend = "http://127.0.0.1:$TEST_NGINX_SERVER_PORT/api-backend/",
          proxy_rules = {
            { pattern = '/', http_method = 'GET', metric_system_name = 'hits', delta = 2 }
          },
          policy_chain = {
            {
              name = 'apicast.policy.3scale_batcher',
              configuration = { }
            },
            {
              name = 'apicast.policy.apicast'
            },
            {
              name = 'apicast.policy.caching',
              configuration = { caching_type = 'resilient' }
            }
          }
        }
      }
    }
  })
}

rewrite_by_lua_block {
  require('resty.ctx').apply()
  ngx.shared.cached_auths:flush_all()
}
--- config
  include $TEST_NGINX_APICAST_CONFIG;

  location /transactions/authorize.xml {
    content_by_lua_block {
      local test_counter = ngx.shared.test_counter or 0
      if test_counter == 0 then
        ngx.shared.test_counter = test_counter + 1
        ngx.status = 200
        ngx.exit(ngx.HTTP_OK)
      else
        ngx.shared.test_counter = test_counter + 1
        ngx.exit(502)
      end
    }
  }

  location /api-backend {
     echo 'yay, api backend';
  }
--- request eval
["GET /test?user_key=foo", "GET /foo?user_key=foo", "GET /?user_key=foo"]
--- response_body eval
["yay, api backend\x{0a}", "yay, api backend\x{0a}", "yay, api backend\x{0a}"]
--- error_code eval
[ 200, 200, 200 ]
--- no_error_log
[error]

=== TEST 6: caches successful authorizations with app_id only
This test checks that the policy a) caches successful authorizations and b) reports correctly.
For a) we define a backend that makes sure that it's called only once.
For b) we force the batch reporting and check that transactions.xml receive it in the expected format.
--- http_config
include $TEST_NGINX_UPSTREAM_CONFIG;
lua_shared_dict cached_auths 1m;
lua_shared_dict batched_reports 1m;
lua_shared_dict batched_reports_locks 1m;
lua_package_path "$TEST_NGINX_LUA_PATH";

init_by_lua_block {
  require('apicast.configuration_loader').mock({
    oidc = {
      {
        issuer = "https://example.com/auth/realms/apicast",
        config = { id_token_signing_alg_values_supported = { "RS256" } },
        keys = { somekid = { pem = require('fixtures.rsa').pub } },
      }
    },
    services = {
      {
        id = 42,
        backend_version = 'oauth',
        backend_authentication_type = 'service_token',
        backend_authentication_value = 'token-value',
        proxy = {
          authentication_method = 'oidc',
          oidc_issuer_endpoint = 'https://example.com/auth/realms/apicast',
          backend = { endpoint = "http://127.0.0.1:$TEST_NGINX_SERVER_PORT" },
          api_backend = "http://127.0.0.1:$TEST_NGINX_SERVER_PORT/api-backend/",
          proxy_rules = {
            { pattern = '/', http_method = 'GET', metric_system_name = 'hits', delta = 1 }
          },
          policy_chain = {
            { name = 'apicast.policy.3scale_batcher', configuration = {} },
            { name = 'apicast.policy.apicast' }
          }
        }
      }
    }
  })
}
--- config
  include $TEST_NGINX_APICAST_CONFIG;

  location /transactions/oauth_authorize.xml {
    content_by_lua_block {
      local test_counter = ngx.shared.test_counter or 0
      if test_counter == 0 then
        ngx.shared.test_counter = test_counter + 1
        ngx.exit(200)
      else
        ngx.log(ngx.ERR, 'auth should be cached but called backend anyway')
        ngx.exit(502)
      end
    }
  }
  location /transactions.xml {
    content_by_lua_block {
      ngx.req.read_body()
      local post_args = ngx.req.get_post_args()
      local app_id_match, usage_match
      for k, v in pairs(post_args) do
        if k == 'transactions[0][app_key]' then
          ngx.exit(500)
        elseif k == 'transactions[0][usage][hits]' then
          usage_match = v == '2'
        elseif k == 'transactions[0][app_id]' then
          app_id_match = v == 'appid'
        end
      end
      ngx.shared.result = usage_match and app_id_match
    }
  }

  location /force_report_to_backend {
    content_by_lua_block {
      local ReportsBatcher = require ('apicast.policy.3scale_batcher.reports_batcher')
      local reporter = require ('apicast.policy.3scale_batcher.reporter')
      local http_ng_resty = require('resty.http_ng.backend.resty')
      local backend_client = require('apicast.backend_client')

      local service_id = '42'

      local reports_batcher = ReportsBatcher.new(
        ngx.shared.batched_reports, 'batched_reports_locks')

      local reports = reports_batcher:get_all(service_id)

      local backend = backend_client:new(
        {
          id = service_id,
          backend_authentication_type = 'service_token',
          backend_authentication_value = 'token-value',
          backend = { endpoint = "http://127.0.0.1:$TEST_NGINX_SERVER_PORT" }
        }, http_ng_resty)

      reporter.report(reports, service_id, backend, reports_batcher)
      ngx.print('force report OK')
    }
  }
  location /check_reports {
    content_by_lua_block {
      if ngx.shared.result then
        ngx.print('report OK')
        ngx.exit(ngx.HTTP_OK)
      else
        ngx.status = 400
        ngx.print('report not OK')
        ngx.exit(ngx.HTTP_OK)
      end
    }
  }
  location /api-backend {
     echo 'yay, api backend';
  }
--- request eval
[ "GET /test", "GET /test", "GET /force_report_to_backend", "GET /check_reports"]
--- error_code eval
[ 200, 200 , 200, 200 ]
--- response_body eval
["yay, api backend\x{0a}","yay, api backend\x{0a}","force report OK", "report OK"]
--- more_headers eval
use Crypt::JWT qw(encode_jwt);
my $jwt = encode_jwt(payload => {
  aud => 'something',
  azp => 'appid',
  sub => 'someone',
  iss => 'https://example.com/auth/realms/apicast',
  exp => time + 3600 }, key => \$::rsa, alg => 'RS256', extra_headers => { kid => 'somekid' });
["Authorization: Bearer $jwt", "Authorization: Bearer $jwt", "" , ""]
--- no_error_log
[error]


=== TEST 7: with caching policy (allow mode)
The purpose of this test is to test that the 3scale batcher policy works
correctly when combined with the caching one.
In this case, the caching policy is configured as "allow". We define a
backend that returns 500
The caching policy will allow all request to the Upstream API.
To make sure that nothing is cached in the 3scale batcher policy, we flush its
auth cache on every request (see rewrite_by_lua_block).
--- http_config
include $TEST_NGINX_UPSTREAM_CONFIG;
lua_shared_dict api_keys 10m;
lua_shared_dict cached_auths 1m;
lua_shared_dict batched_reports 1m;
lua_shared_dict batched_reports_locks 1m;
lua_package_path "$TEST_NGINX_LUA_PATH";

init_by_lua_block {
  require('apicast.configuration_loader').mock({
    services = {
      {
        id = 42,
        backend_version = 1,
        backend_authentication_type = 'service_token',
        backend_authentication_value = 'token-value',
        proxy = {
          backend = { endpoint = "http://127.0.0.1:$TEST_NGINX_SERVER_PORT" },
          api_backend = "http://127.0.0.1:$TEST_NGINX_SERVER_PORT/api-backend/",
          proxy_rules = {
            { pattern = '/', http_method = 'GET', metric_system_name = 'hits', delta = 2 }
          },
          policy_chain = {
            {
              name = 'apicast.policy.3scale_batcher',
              configuration = { }
            },
            {
              name = 'apicast.policy.apicast'
            },
            {
              name = 'apicast.policy.caching',
              configuration = { caching_type = 'allow' }
            }
          }
        }
      }
    }
  })
}

rewrite_by_lua_block {
  require('resty.ctx').apply()
  ngx.shared.cached_auths:flush_all()
}
--- config
  include $TEST_NGINX_APICAST_CONFIG;

  location /transactions/authorize.xml {
    content_by_lua_block {
      ngx.exit(500)
    }
  }

  location /api-backend {
     echo 'yay, api backend';
  }
--- request eval
["GET /test?user_key=foo", "GET /foo?user_key=foo", "GET /?user_key=foo"]
--- response_body eval
["yay, api backend\x{0a}", "yay, api backend\x{0a}", "yay, api backend\x{0a}"]
--- error_code eval
[ 200, 200, 200 ]
--- no_error_log
[error]
