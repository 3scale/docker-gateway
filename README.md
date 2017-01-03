
# **WARNING**: this is documentation for development branch, that might not be working at any point. To see stable version go to [`master` branch](https://github.com/3scale/apicast/tree/master).

APIcast is an NGINX based API gateway used to integrate your internal and external API services with 3scale’s API Management Platform.

To learn more about deployment options, environments provided, and how to get started, go to the [APIcast overview](doc/overview.md).

# APIcast

`v2` branch is **not stable** yet and **not recommended for production** use.

## Description

This Dockerfile creates a [3scale](http://www.3scale.net) gateway, and configures itself according to your 3scale params.

## OpenShift

To run APIcast on OpenShift, just use template and create a Secret to point to your 3scale Admin Portal.

```shell
oc secret new-basicauth threescale-portal-endpoint-secret --password=https://ACCESS-TOKEN@ACCOUNT-admin.3scale.net
oc new-app -f https://raw.githubusercontent.com/3scale/apicast/v2/openshift/apicast-template.yml
```

## Docker

You can download a ready to use Docker image from our repository:

```shell
docker pull quay.io/3scale/apicast:v2
```

The 3scale gateway image requires one of two environment variables. The first option will pull the latest gateway configuration from the 3scale API Manager. The second points to a local configuration file which has already been downloaded from 3scale:

* **THREESCALE_PORTAL_ENDPOINT**

URI that includes your password and portal endpoint in following format: `schema://access-token@domain`. The password can be either the [provider key](https://support.3scale.net/docs/terminology#apikey) or an [access token](https://support.3scale.net/docs/terminology#tokens) for the 3scale Account Management API. Note: these should not be confused with [service tokens](https://support.3scale.net/docs/terminology#tokens)
Example: https://ACCESS-TOKEN@ACCOUNT-admin.3scale.net (where the host name is the same as the domain for the URL when you are logged into the admin portal from a browser.

When `THREESCALE_PORTAL_ENDPOINT` environment variable is provided, the gateway will download the configuration from the 3scale on initializing. The configuration includes all the settings provided on the Integration page of the API(s).

```shell
docker run --name apicast --rm -p 8080:8080 -e THREESCALE_PORTAL_ENDPOINT=https://ACCESS-TOKEN@ACCOUNT-admin.3scale.net quay.io/3scale/apicast:v2
```

* **THREESCALE_CONFIG_FILE**

Path to saved JSON file with configuration for the gateway. The configuration can be downloaded from the 3scale admin portal using the URL https://ACCOUNT-admin.3scale.net/admin/api/nginx/spec.json (replace `ACCOUNT` with your 3scale account name). The file has to be injected to the docker image as read only volume, and the path should indicate where the volume is mounted, i.e. path local to the docker container.

```shell
docker run --name apicast --rm -p 8080:8080 -v $(pwd)/config.json:/opt/app/config.json:ro -e THREESCALE_CONFIG_FILE=/opt/app/config.json quay.io/3scale/apicast:v2
```

In this example `config.json` is located in the same directory where the `docker` command is executed, and it is mounted as a volume at `/opt/app/config.json`. `:ro` indicates that the volume will be read-only.

The JSON file needs to follow the [schema](schema.json), see an [example file](examples/configuration/example-config.json) with the fields that are used by the gateway.

In some 3scale plans it is possible to create multiple API services (see an [example of the configuration file](examples/configuration/multiservice.json)). The _optional_ **APICAST_SERVICES** environment variable allows filtering the list of services, so that the gateway only includes the services explicitly specified, the value of the variable should be a comma-separated list of service IDs. This setting is useful when you have many services configured on 3scale, but you want to expose just a subset of them in the gateway.

```shell
docker run --name apicast --rm -p 8080:8080 -e THREESCALE_PORTAL_ENDPOINT=https://ACCESS-TOKEN@ACCOUNT-admin.3scale.net -e APICAST_SERVICES=1234567890987 quay.io/3scale/apicast:v2
```

### Docker options

Here are some useful options that can be used with `docker run` command:

- `--rm`
Automatically remove the container when it exits

- `-d` or `--detach`
Run container in background and print container ID. When it is not specified, the container runs in foreground mode, and you can stop it by `CTRL + c`. When started in detached mode, you can reattach to the container with the _docker attach_ command, for example, `docker attach apicast`.

- `-p` or `--publish` Publish a container's port to the host. The value should have the format `<host port>:<container port>`, so `-p 80:8080` will bind port `8080` of the container to port `80` of the host machine.

 For example, the [Management API](doc/management-api.md) uses port `8090`, so you may want to publish this port by adding `-p 8090:8090` to the `docker run` command.

- `-e` or `--env` Set environment variables
- `-v` or `--volume` Mount a volume. The value is typically represented as `<host path>:<container path>[:<options>]`. `<options>` is an optional attribute, it can be set to `:ro` to specify that the volume will be read only (it is mounted in read-write mode by default). Example: `-v /host/path:/container/path:ro`.

See the Docker [commands reference](https://docs.docker.com/engine/reference/commandline/) for more information on available options.

### Auto updating

The gateway is able of checking the configuration from time to time and self update, you can enable this by adjusting the AUTO_UPDATE_INTERVAL (seconds) to some value greater than 60:

```
-e AUTO_UPDATE_INTERVAL=300
```

This variable is set to 0 by default.

### Signals

Signals are the same as normal NGINX.

Use `docker kill -s $SIGNAL CONTAINER` to send them, where _CONTAINER_ is the container ID or name.

# Development & Testing

## Tools and dependencies

For developing and testing APIcast the following tools are needed:

- [OpenResty](http://openresty.org/en/) - a bundle based on NGINX core and including LuaJIT and Lua modules. Follow the [installation instructions](http://openresty.org/en/installation.html) according to your OS.

- [LuaRocks](https://luarocks.org/) - the Lua package manager.
 You can find [installation instructions](https://github.com/keplerproject/luarocks/wiki/Download#installing) for different platforms in the documentation.
 For Mac OS X the following [Homebrew](http://brew.sh/) formula can be used:
 ```shell
 brew install apitools/openresty/luarocks
 ```

- [busted](http://olivinelabs.com/busted/) - unit testing framework, used for unit testing.
 ```shell
 luarocks install busted
 ```

- [Test::Nginx](http://search.cpan.org/~agent/Test-Nginx-0.25/lib/Test/Nginx/Socket.pm) – used for integration testing.
 ```shell
 cpan install Carton
 cpan install Test::Nginx
 ```

- [redis](http://redis.io/) in-memory data store is used for caching. The tests for the OAuth flow require a redis instance running on `localhost`.

- Docker and `s2i`

 There are tests that run in Docker container, to execute these Docker needs to be installed, and to build the images [Source-To-Image](https://github.com/openshift/source-to-image) is used. To install it, download it from the [releases page](https://github.com/openshift/source-to-image/releases), and put the extracted `s2i` executable on your PATH.

## Running the tests

To run all the tests at once, execute:

```shell
make test
```

To run just the unit tests:

```shell
make busted
```

To run just the integration tests:

```shell
make prove
```

To see additional test targets (such as testing produced Docker images) use:
```shell
make help
```

# Contributing
For details on how to contribute to this repo see [CONTRIBUTING](.github/CONTRIBUTING.md)
