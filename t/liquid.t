use lib 't';
use Test::APIcast::Blackbox 'no_plan';

# Parsing only occurs when loading the config, so we will only see the Liquid
# error in the first request.
repeat_each(1);

run_tests();

__DATA__

=== TEST 1: invalid liquid in the config
When there is an invalid Liquid in the config, APIcast:
1) Does not crash.
2) Shows an error.
3) Evaluates the invalid Liquid as and empty string (Notice the arg added by
the URL rewriting policy in the response.
--- configuration
{
  "services": [
    {
      "id": 42,
      "proxy": {
        "policy_chain": [
          {
            "name": "apicast.policy.url_rewriting",
            "configuration": {
              "query_args_commands": [
                {
                  "op": "set",
                  "arg": "new_arg",
                  "value": "{{'something' | md5",
                  "value_type": "liquid"
                }
              ]
            }
          },
          {
            "name": "apicast.policy.upstream",
            "configuration": {
              "rules": [
                {
                  "regex": "/",
                  "url": "http://test:$TEST_NGINX_SERVER_PORT"
                }
              ]
            }
          }
        ]
      }
    }
  ]
}
--- upstream
  location / {
    content_by_lua_block {
      local luassert = require('luassert')

      -- Verify here that the new arg was set to empty
      luassert.equals('', ngx.req.get_uri_args()['new_arg'])

      ngx.say('yay, api backend')
    }
  }
--- request
GET /
--- error_code: 200
--- error_log
Invalid Liquid: {{'something' | md5
