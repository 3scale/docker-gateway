# APIcast

[![CircleCI](https://circleci.com/gh/3scale/APIcast/tree/master.svg?style=shield)](https://circleci.com/gh/3scale/APIcast/tree/master)
[![Docker Repository on Quay](https://quay.io/repository/3scale/apicast/status "Docker Repository on Quay")](https://quay.io/repository/3scale/apicast)
[![codecov](https://codecov.io/gh/3scale/apicast/branch/master/graph/badge.svg)](https://codecov.io/gh/3scale/apicast)

APIcast is an API gateway built on top of [NGINX](https://www.nginx.com/). It is
part of the [Red Hat 3scale API Management
Platform](https://www.redhat.com/en/technologies/jboss-middleware/3scale).

- [**Getting started**](#getting-started)
- [**Features**](#features)
- [**Development**](#development)
- [**Documentation**](#documentation)
- [**License**](#license)

## Getting started

`master` branch is **not recommended** for production use. For the latest
release, go to the [Releases page](https://github.com/3scale/apicast/releases)

### Docker

You need to specify an `ACCESS_TOKEN`, that you can get from the 3scale admin
portal, and also your `ADMIN_PORTAL_DOMAIN`. If you are using SaaS, it is
`YOUR_ACCOUNT-admin.3scale.net`.

```shell
docker run --name apicast --rm -p 8080:8080 -e THREESCALE_PORTAL_ENDPOINT=https://ACCESS_TOKEN@ADMIN_PORTAL_DOMAIN quay.io/3scale/apicast:master
```

You can use a JSON configuration file instead:

```shell
docker run --name apicast --rm -p 8080:8080 -v $(pwd)/config.json:/opt/app/config.json:ro -e THREESCALE_CONFIG_FILE=/opt/app/config.json quay.io/3scale/apicast:master
```

In this example `config.json` is located in the same directory where the
`docker` command is executed, and it is mounted as a volume at
`/opt/app/config.json`. `:ro` indicates that the volume will be read-only.

The JSON file needs to follow the [schema](schema.json), see an [example
file](examples/configuration/example-config.json) with the fields that are used
by APIcast.

### Openshift

You need to create a secret with your `ACCESS_TOKEN` and your `ADMIN_PORTAL_DOMAIN`:

```shell
oc create secret generic apicast-configuration-url-secret \
   --from-literal=password=https://ACCESS_TOKEN@ADMIN_PORTAL_DOMAIN \
   --type=kubernetes.io/basic-auth
oc new-app -f https://raw.githubusercontent.com/3scale/apicast/master/openshift/apicast-template.yml
```

### OKD (Openshift-origin 3.11)

Using yaml files is the common approach to configure 3scale APIcast on Openshift origin. Another approach is pulling a 3scale image on the local docker repository, then creating a new application in OKD from the Docker image by passing required parameters. For example, this latter approach was used to setup 3scale APIcast in OKD cluster on AWS.

- Pull the 3scale image to the local docker repository:

docker pull registry.access.redhat.com/3scale-amp20/apicast-gateway:1.0

In all cases, in order to setup 3scale you need to have 3scale account. Steps to create and configure 3scale account are given here (https://github.com/tnscorcoran/rhsso-3scale).

- Once configured 3scale account, you need 'ACCESS_TOKEN' along with your 3scale account URL which is called `ADMIN_PORTAL_DOMAIN`, to create secret which in turn used by your application for authentication. Create secret as discussed in the above approach.

oc create secret generic apicast-configuration-url-secret --from-literal=password=https://2040edXXXXXXXXX80d6@XXXXX-admin.3scale.net --type=kubernetes.io/basic-auth

. Using 'ACCESS_TOKEN' and 'ADMIN_PORTAL_DOMAIN', you can configure another environment variable 'THREESCALE_PORTAL_ENDPOINT':

THREESCALE_PORTAL_ENDPOINT=https://ACCESS_TOKEN@ADMIN_PORTAL_DOMAIN

- In order to create application using local 3scale docker image, you need to pass environment variables

oc new-app --docker-image=registry.access.redhat.com/3scale-amp20/apicast-gateway:1.0  --param CONFIGURATION_URL_SECRET=apicast-configuration-url-secret -e THREESCALE_PORTAL_ENDPOINT=https://2040edXXXXXXXXX80d6@XXXXX-admin.3scale.net

This should setup 3scale APIcast on your all in one OKD cluster.


## Features

- Performance: it is fast because it's built on top of [NGINX](https://www.nginx.com/) and uses [LuaJIT](https://luajit.org/).
- Scalability: APIcast is stateless, so it scales horizontally.
- Request transformation: allows to modify the headers, the path and the arguments of a request.
- Rate-limit: can apply limits based on a header, [JWT](https://jwt.io/) claims, the IP of the request and many more.
- Modular and extensible: thanks to the APIcast [policies framework](doc/policies.md).
- Monitoring with [Prometheus](https://prometheus.io/).
- [OpenTracing](https://opentracing.io/) integration with [Jaeger](https://www.jaegertracing.io/).
- Can be deployed in [Openshift](https://www.openshift.com/).
- Integrates with IDPs like [Keycloak](https://www.keycloak.org) to provide authentication based on [OIDC](https://openid.net/connect/).


## Development

Using Docker you just need to run:
```shell
make development
```

That will create a Docker container and run bash inside it. The project's source
code will be available in the container and sync'ed with your local `apicast`
directory, so you can edit files in your preferred environment and still be able
to run whatever you need inside the Docker container.

To install the dependencies inside the container run:
```shell
make dependencies
```

To run the unit tests inside the container:
```shell
make busted
```

To run the integration tests inside the container:
```shell
make prove
```

To learn about the other available make targets:
```shell
make help
```

APIcast uses:

- [OpenResty](http://openresty.org/en/): a platform that includes NGINX, LuaJIT and Lua modules.
- [busted](https://github.com/Olivine-Labs/busted): for the unit tests.
- [Test::Nginx](http://search.cpan.org/~agent/Test-Nginx/lib/Test/Nginx/Socket.pm): for the integration tests.

## Documentation

- [Configuration parameters](doc/parameters.md)
- [Get started with Lua and OpenResty](doc/policy-development.md)
- [Learn about policies and write your own](doc/policies.md)
- [Available Prometheus metrics](doc/prometheus-metrics.md)
- [Management API](doc/management-api.md)
- [Contribute](.github/CONTRIBUTING.md)


## License
[Apache 2.0](LICENSE)
