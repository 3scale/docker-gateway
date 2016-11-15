Running Apicast with OAuth 
==========================

The API Gateway has a dependency on Redis when adding OAuth support. 

In this case, docker-compose has to be run in order to start up all of the required components. 

The command to do so is 

`docker-compose up -d`

from the directory containing the docker-compose.yml file (in this case /apicast/examples/oauth2)

The `-d` flag starts the containers up in detached mode, if you want to see the output when starting the containers, you should omit this. 

In order for the command to run successfully, you will also need a .env file with the following content:

```
# URI to fetch gateway configuration from. Expected format is: https?://[password@]hostname
THREESCALE_PORTAL_ENDPOINT=https://access_token@example-admin.3scale.net


# Path to a file mounted into docker container that contains the gateway configuration.
# That can be for example cached response from the API.
# THREESCALE_CONFIG_FILE

# Redis host. Used to store access tokens.
REDIS_HOST=redis
# REDIS_PORT=6379

# Limit to subset of services. Comma separated list of service ids.
# APICAST_SERVICES=265,31,42


# What to do when Apicast does not have configuration. Allowed values are: log, exit
# APICAST_MISSING_CONFIGURATION=log

IMAGE_NAME=apicast-test
```

The docker compose file spins up 3 services:

1. APIcast
2. Redis 
3. A very simple "Authorization Server" (auth-server) written in Ruby

3scale Setup
------------

To get this working with a 3scale instance 


Alternatively, you can use sample_config.json to run this instead. 



Requesting an access token
--------------------------

Once you have APIcast configured to point to your local oauth testing instance, you can use a tool such as POSTMAN to request an access token. 

You will need to have an application set up in 3scale and set the redirect url to `
https://www.getpostman.com/oauth2/callback` 

The Auth URL will be the /authorize endpoint on your API Gateway instance.
The Access Toekn URL will be the /oauth/token endpoint on your API Gateway instance. 

You can then click "Request Token" to initiate the access token request process. 

auth-server.rb
--------------

A very simple Sinatra app acting as an Authorization Server. 

The app will display a log in page (/auth/login) which will accept any values for username and password.
Once logged in, a consent page will be displayed to accept or deny the request. 

The authorization server will callback apicast to issue an authorization code on request acceptance and the redirect_uri directly on denial. 

Once the Authorization Code is sent to the redirect url ( POSTMAN callback endpoint in this case ) the exchange of authorization code for an access token is done transparently by POSTMAN behind the scenes. 
