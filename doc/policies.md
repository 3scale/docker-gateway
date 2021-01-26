# APIcast policies

The behavior of APIcast is customizable via policies. A policy basically tells
APIcast what it should do in each of the NGINX phases. This document details
how policies work and how you can write your own and integrate them into
APIcast.

- [**Policies**](#policies)
- [**Policy chains**](#policy-chains)
- [**APIcast default policies**](#apicast-default-policies)
- [**Write your own policy**](#write-your-own-policy)
- [**Integrate your policies**](#integrate-your-policies)
- [**Available policies**](#available-policies)


## Policies

A policy tells APIcast what it should do in each of the nginx phases: `init`,
`init_worker`, `ssl_certificate`, `rewrite`, `access`,`content`, `balancer`, `header_filter`, `body_filter`,
`post_action`, `log`, and `metrics`.

Policies can share data between them. They do that through what we call the
`context`. Policies can read from and modify that context in every phase.

All phases except `init`, `init_worker` and `metrics` can be evaluated when
proxying a request. `metrics` is evaluated when [Prometheus](https://prometheus.io)
gets data from the metrics endpoint. `init` and `init_worker` are evaluated
when starting the gateway.

## Policy chains

Policies can be combined using a policy chain. A policy chain is simply a
sorted list of policies.

The way policy chains work is as follows: suppose that we have a policy A that
describes what to do in the `rewrite` and `header_filter` phases and a policy B
that describes what to run in `access` and `header_filter`. Assume also that
when describing the chain, we indicate that policy A should be run before
policy B. 
When APIcast receives an HTTP request, it will check the policy chain
and perform the tasks outlined in the following table:

| Phase    | APIcast tasks                                           |
|----------|---------------------------------------------------------|
| rewrite  | Executes the function policy A provides for this phase. |
| access   | Executes the function policy B provides for this phase. |
| content  | None. Neither policy A nor B  describes what to do.     |
| balancer | None. Neither policy A nor B  describes what to do.     |
| header_filter  | Executes the function policy A provides for this phase and then the function policy B provides for this phase. Policy chains define an order, and we specified that policy A comes before policy B |
| body_filter   | None. Neither policy A nor B  describes what to do. |
| post_action  | None. Neither policy A nor B  describes what to do.     |
| log | None. Neither policy A nor B  describes what to do.     |


Notice that there is not a description of what APIcast does in the `init` and the
`init_worker` phases. The reason is that those two are not executed in every
request. `init` is executed when APIcast boots, and `init_worker` when each
of its workers starts.

Another phase that is not executed for every request is `ssl_certificate` because
it is called only when APIcast terminates the HTTPS connection.

The order in which policies actions are applied depends on two factors:
- Position of the policy within the policy chain.
- The phase in which the policies act.

This means that sometimes the outcome of the policies execution may be affected
by other policies which are located further in the policy chain.

For example, suppose that we combine the APIcast policy (the default one),
with the URL rewriting one (which modifies the URL path based on some defined
rules). If the URL rewriting policy appears before the APIcast one, the
mapping rules of APIcast will be applied against the rewritten path.
However, if the URL policy appears after the APIcast one, the mapping rules
will be applied against the original path.

Regarding policies that run on the `content` phase, it is important to bear in
mind that only the one that comes first in the chain will output content to the
response.
Suppose that we combine the `APIcast` policy and the `upstream` one.
The `APIcast` policy will try to proxy the request to the upstream defined in
the configuration of the service, whereas the `upstream` policy will try to
proxy it to a different one if the request path matches the pattern defined
in the policy config. Whichever of those 2 policies comes first will output
content to the response. When the second gets a chance to run its content
phase, the request will already be sent to the client, so it will not output
anything to the response.

### Types

There are two types of policy chains in APIcast: per-service chains and a
global chain. Both of them can be configured.

As the name indicates, per-service chains allow us to define a specific chain
for a given service. This means that we can apply different policies to our
services, or the same policies but configured differently, or in a different
order. On the other hand, there's only one global chain, and the behavior it
defines applies to all the services.


## APIcast default policies

By default, APIcast applies the `apicast` policy to all the services. This
policy includes all the functionality offered by APIcast (mapping rules
matching, authorization and reporting against 3scale backend, etc.). In the
future, this policy will be split and each of the resulting policies will be
replaceable with custom ones.

## Write your own policy

### Policy structure

The policy is expected to have some structure, so APIcast can find it. Minimal policy structure consists of two files: `init.lua` and `apicast-policy.json`.

Custom policies are expected to be on the following paths:

* `APICAST_DIR/policies/${name}/${version}/`

And builtin ones also on:

* `APICAST_DIR/src/apicast/policy/${name}/`

All files in the policy directory are namespaced, so you can move the dependencies to the `/vendor' directory.  Consider the following structure:

```
APICAST_DIR/policies/my_stuff/1.0/
APICAST_DIR/policies/my_stuff/1.0/init.lua
APICAST_DIR/policies/my_stuff/1.0/my_stuff.lua
APICAST_DIR/policies/my_stuff/1.0/vendor/dependency.lua
APICAST_DIR/policies/my_stuff/1.0/apicast-policy.json
```

The first file to be loaded will be `init.lua`. That is the only Lua file APIcast cares about.
For better code organization we recommend that file to have just very simple implementation like:

```lua
return require('my_stuff')
```

And actually implement everything in `my_stuff.lua`. This makes the policy file easier to find by humans.

If the policy requires third-party dependencies. Those can be put anywhere in the policy structure and will be available. Imagine it as UNIX `chroot`. So for example `require('vendor/dependency')` will load `APICAST_DIR/policies/my_stuff/1.0/vendor/dependency.lua` when loading your policy.

The policy has access to only code it provides and shared code in `APICAST_DIR/src/`.

You can start APIcast with different policy load path parameter (`--policy-load-path` or `APICAST_POLICY_LOAD_PATH`) to load
policies from different than the default path. Example:
```shell
bin/apicast start --policy-load-path examples/policies:spec/fixtures/policies
```

For more details see [examples/policies/README.md](../examples/policies/README.md).

### Policy code

To write your own policy you need to write a Lua module that instantiates a
[Policy](../gateway/src/apicast/policy.lua) and defines a method for
each of the phases where it needs to execute something.

Suppose that we wanted to run a policy that logged a message in the `rewrite`
and the `header_filter` phases. This is how our module would look
like:
```lua
local policy = require('apicast.policy')
local _M = policy.new('My custom policy')

function _M:rewrite()
  ngx.log(ngx.INFO, 'Passing through the rewrite phase.')
end

function _M:header_filter()
  ngx.log(ngx.INFO, 'Passing through the header_filter phase')
end

return _M
```

If we wanted to read or write in the `context`:
```lua
function _M:rewrite(context)
  -- Read something from the context.
  local smth = context.something

  -- Write 'b' into the context so other policies or later phases can read it.
  context.b = 'something_useful_to_be_shared'
end
```

Policies can also have a configuration:
```lua
local policy = require('apicast.policy')
local _M = policy.new('My custom policy')
local new = _M.new

function _M.new(config)
  local self = new()

  -- 'config' contains two params that define the behaviour of our policy and
  -- we want to access them from other phases.
  self.option_a = config.option_a
  self.option_b = config.option_b

  return self
end
```

In the [policy folder](../gateway/src/apicast/policy) you can find several
policies. These ones are quite simple and can be used as examples to write your
own:
- [Echo](../gateway/src/apicast/policy/echo)
- [Phase logger](../gateway/src/apicast/policy/phase_logger)
- [CORS](../gateway/src/apicast/policy/cors)
- [Headers](../gateway/src/apicast/policy/headers)

### Policy scaffolding

We provide a policy generator to make this process easier and create a basic structure for you.
Policy scaffolding generator will provide you with the structure for your code,
policy manifest, unit tests and integration tests.
Invoke `bin/apicast generate policy --help` and follow the documentation.

## Integrate your policies

Policies can be configured using the 3scale UI, but you can also configure them
in APIcast using a configuration file. Remember that APIcast allows specifying a
config file using the `THREESCALE_CONFIG_FILE` env variable:
```shell
THREESCALE_CONFIG_FILE=my_config.json bin/apicast
```

Policies are specified in the `proxy` object of each service. A policy chain is
a JSON array where each object represents a policy with a name and an optional
configuration. Notice that the configuration is received in the `new` method of
the policy as shown above.

Here's an example that shows how to define a policy chain with the CORS policy
and the APIcast one. Please note that the configuration of services is more
complex than shown here. This is a very simplified version to illustrate how
policies can be configured:
```json
{
  "services":[
    {
      "id":42,
      "proxy":{
        "policy_chain":[
          {
            "name":"cors", "version": "builtin",
            "configuration":{
              "allow_headers":["X-Custom-Header-1","X-Custom-Header-2"],
              "allow_methods":["POST","GET","OPTIONS"],
              "allow_origin":"*",
              "allow_credentials":false
            }
          },
          {
            "name":"apicast", "version": "builtin"
          }
        ]
      }
    }
  ]
}
```

If instead of configuring the policy chain of a specific service, you want to
customize the global policy chain, you can take a look at
[this example](../examples/policy_chain/README.md).

## Available policies

When configuring your policies using the 3scale UI, the policies available
depend on the 3scale deployment type (on-premises or SaaS). The built-in
policies (headers, upstream, url_rewriting, etc.) are always available. However,
it is not always possible to use custom policies:
- On-premises: custom policies are available.
- SaaS (APIcast hosted by 3scale): the policies available are the ones included
in the APIcast hosted by 3scale,
[apicast-cloud-hosted](https://github.com/3scale/apicast-cloud-hosted). It is
not possible to use custom policies.
- SaaS (self-hosted APIcast): the 3scale UI shows the policies provided in the
APIcast hosted by 3scale. However, it is possible to use custom ones if they are
included in APIcast as explained in the [Write your own
policy](#write-your-own-policy) section. In order to use custom policies, they
need to be included in the config file as explained in [Integrate your
policies](#integrate-your-policies). You can download the config file from
3scale and use it as a starting point. Notice that with this option, if you make
a change using the 3scale UI, you'll need to update your config file too.
