# Run the policy locally

Now that the development and unit testing of the policy is completed it is time to actually start APIcast with the newly created policy. This way we can verify the policy actually works inside the Nginx process. We are again going to use the APIcast development Docker image to run APIcast with our newly created policy.

## Create APIcast configuration

APIcast can be provisioned in two ways, either automatically from the 3scale API Manager or via a json configuration file. Since the custom policy is not available in the 3scale API Manager we need to configure APIcast with the json configuration file. In this configuration file we are also going to leverage the build-in echo service of APIcast so we can test the policy and receive an upstream response without running a full 3scale API Manager configuration.

The part of the json configuration file detailing the configuration of our policy need to adhere to the json schema we defined earlier.

The location of the config file is somewhat arbitrary as long as the APIcast process can access the file. In this example we are going to create the following file **‘hello_world_config.json’** in the **apicast/examples/configuration** directory.

The contents of the configuration file is:

```json
{
  "services": [
    {
      "proxy": {
        "policy_chain": [
          {
            "name": "hello_world",
            "version": "builtin",
            "configuration": {
              "overwrite": true,
              "secret": "mysecret"
            }
          },
          {
            "name": "apicast.policy.upstream",
            "configuration": {
              "rules": [
                {
                  "regex": "/",
                  "url": "http://echo:8081"
                }
              ]
            }
          }
        ]
      }
    }
  ]
}
```

Inside the policy chain we first configure our hello_world policy with the overwrite and secret properties. Second in the policy chain is the upstream policy which acts as an echo mock service so we can actually receive a response.

### Starting the APIcast server
Now in order to start the APIcast server with the hello_world_configuration.json file inside the development container issue the following command:

```shell
bash-4.2$ bin/apicast --log-level=debug --dev -c examples/configuration/hello_world_config.json
```

the bin/apicast executable starts the apicast server, we set the log-level to debug which is going to result in an incredible amount of debug logging.
If the amount of debug logging is a bit too much for you the log-level can also be set to **notice** this results in a lot fewer log lines, but still the custom log entries in the policy are logged.

### Executing test requests
Now that we have our APIcast server up and running let’s test if the hello_world policy actually works.

To test this we need to issue an HTTP request to the APIcast server. However the development Docker container does not expose any ports. We could alter either the makefile or the Docker compose file to expose the ports. But in this example we are simply going to create another bash session the the development container and issue a curl request from inside the container.

To create a second bash session open a new terminal window and find the Docker container id of the APIcast development image using the following command:

```shell
$ docker ps
CONTAINER ID        IMAGE                                         COMMAND                  CREATED             STATUS              PORTS               NAMES
5a72c49671c5        quay.io/3scale/s2i-openresty-centos7:master   "container-entrypoin…"   2 hours ago         Up 2 hours          8080/tcp            apicast_build_0_development_1_802efce654d5
366c62d0bccf        redis                                         "docker-entrypoint.s…"   2 hours ago         Up 2 hours          6379/tcp            apicast_build_0_redis_1_469bce65a85a
```

The make development command we used to start the APIcast development container actually starts two containers one with the APIcast development environment, the second with a Redis cache. The container we are interested is the container with the image: **quay.io/3scale/s2i-openresty-centos7:master**

In the above example it has the id of **5a72c49671c5** off course yours will be different. Now that we know the ID of the container let’s create a new bash session using the following command:

```shell
$ docker exec -it 5a72c49671c5 /bin/bash
```

Now we have another interactive bash shell in the APIcast development container and we can issue the HTTP request to test the policy from here.

In the container issue the following HTTP request:

```shell
$ curl localhost:8080
<html>
<head><title>403 Forbidden</title></head>
<body bgcolor="white">
<center><h1>403 Forbidden</h1></center>
<hr><center>openresty/1.13.6.2</center>
</body>
</html>
```

The response will be a 403 Forbidden. Let’s look at the logs to see what has happened.

```shell
$ bin/apicast --log-level=notice --dev -c examples/configuration/hello_world_config.json
loading production environment configuration: /home/centos/gateway/config/production.lua
loading development environment configuration: /home/centos/gateway/config/development.lua
2019/04/29 09:32:33 [notice] 257#257: [lua] environment.lua:194: add(): loading environment configuration: /home/centos/gateway/config/production.lua
2019/04/29 09:32:33 [notice] 257#257: [lua] environment.lua:194: add(): loading environment configuration: /home/centos/gateway/config/development.lua
2019/04/29 09:32:33 [notice] 257#257: using the "epoll" event method
2019/04/29 09:32:33 [notice] 257#257: openresty/1.13.6.2
2019/04/29 09:32:33 [notice] 257#257: built by gcc 4.8.5 20150623 (Red Hat 4.8.5-28) (GCC)
2019/04/29 09:32:33 [notice] 257#257: OS: Linux 4.4.0-146-generic
2019/04/29 09:32:33 [notice] 257#257: getrlimit(RLIMIT_NOFILE): 1048576:1048576
2019/04/29 09:43:17 [notice] 257#257: *6 [lua] hello_world.lua:53: request is not authorized, secrets do not match, client: 127.0.0.1, server: _, request: "GET / HTTP/1.1", host: "localhost:8080"
[29/Apr/2019:09:43:17 +0000] localhost:8080 127.0.0.1:40946 "GET / HTTP/1.1" 403 175 (0.000) 0
```

The APIcast is running with the notice log-level, when started with the debug log-level considerable more log events will be present. But the one we are interested in is the second from the bottom.

Which states: **‘request is not authorized, secrets do not match’** which is put in the log by the following line in the policy code:

```lua
if secret_header ~= self.secret then
 ngx.log(ngx.NOTICE, "request is not authorized, secrets do not match")
 ngx.status = 403
 return ngx.exit(ngx.status)
```

So we now our policy is executing. Let’s provide the secret header in our request in order to pass the validation. Issue the following HTTP request:

```shell
$ curl localhost:8080 -H 'secret: mysecret'
GET / HTTP/1.1
X-Real-IP: 127.0.0.1
Host: echo
User-Agent: curl/7.29.0
Accept: */*
secret: mysecret
```

Now we received a valid 200 response from the echo server. But the actual rewrite of query parameters to header is not tested, since the request did not contain any query parameters. So issue a new request with a query parameter to see the transformation at work. Issue the following request:

```shell
$ curl localhost:8080?myparam=myvalue -H 'secret: mysecret'
GET /?myparam=myvalue HTTP/1.1
X-Real-IP: 127.0.0.1
Host: echo
User-Agent: curl/7.29.0
Accept: */*
secret: mysecret
myparam: myvalue
```

Now we see in the response the header myparam:myheader