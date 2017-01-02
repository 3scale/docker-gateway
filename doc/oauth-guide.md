# Using 3scale API Gateway with OAuth

## Pre-requisites

APIcast offers support for the OAuth Authorization Code flow out of the box as long as the following pre-requisites are met:

- An Authorization Server as defined in [RFC6749#1.1](https://tools.ietf.org/html/rfc6749#section-1.1) with the one exception that the access tokens will be issued by APIcast instead. In this case the Authorization Server will only authenticate the resource owner and obtain their authorization.
- A [Redis](https://redis.io) instance.

## APIcast Configuration in 3scale Admin Portal

In order to configure this, we will first need to choose the OAuth Authentication method from the Integration Settings ( **API > Integration > "edit integration settings"** ) screen on our 3scale Admin portal. We will also need to ensure we have selected the Self Managed Gateway option, as it is not currently possible to run APIcast with OAuth Authorization Code support on the APIcast cloud gateway. 

Once that is done, we will see an additional field in the Integration Screen ( **API > Integration** ) under "Authentication Settings": "OAuth Authorization Endpoint". Here we define where Resource Owners will be redirected to in order to authenticate and confirm they authorize a given client access to their resources (as per [RFC6749#4.1](https://tools.ietf.org/html/rfc6749#section-4.1.1)). 

All other fields on the Integration Screen should be configured as per the "APIcast Overview" document. Since we will be running all components locally for this example, my "Public Base URL" where APIcast is running will be `http://localhost:8080`.

In order to show a sample integration with an Authorization Server we will use a very simple ruby app to act as an Authorization Server. This app will run on localhost port 3000 with the authorization endpoint at `http://localhost:3000/auth/login`.

The sample code for this app can be found in the `apicast/examples` directory under `oauth2/auth-server`. There we can also find a `docker-compose.yml` file to allow us to deploy a test environment to test our API Integration and OAuth2 Authorization Code Flow. 

## Running APIcast with OAuth

In order to start APIcast in OAuth mode, we will first need to have a redis instance running and pass in the instance details when running APIcast.

In our case, this is running on `localhost:6379`. Since this is running on the default port, we only need to specify `REDIS_HOST`, if this were running on any other port, we would also have to specify `REDIS_PORT`. We can then start APIcast like so:

```shell
REDIS_HOST=localhost THREESCALE_PORTAL_ENDPOINT=https://MY_PROVIDER_KEY@MY_ADMIN_PORTAL.3scale.net bin/apicast -v
```

Here we have added the `-v` flag to run APIcast in verbose mode, in order to allow us to get more debugging output in case anything goes wrong, but this can be omitted.

Our Authorization Server should also be up and running and ready to receive requests.

## Testing the Flow

In order to test that our API is integrated correctly we will act as a Developer would and use a sample client to request an access token from APIcast. This is another simple ruby app that will act as a client (as per the client role defined in [RFC6749#1.1](https://tools.ietf.org/html/rfc6749#section-1.1).) The sample code for the client app can be found in the `apicast/examples` folder under `oauth2/client`.

We will be running this application on `localhost:3001`. The application has a `/callback` endpoint defined to receive and process any authorization codes and access tokens from APIcast. As such, this location will need to be set up on our 3scale account, under a test application, as the *Redirect URL*.

### Requesting an Authorization Code

Once that is all in place, we can run our client application and navigate to `http://localhost:3001`. Here we can enter a `client_id`, `redirect_uri` and `scope`, then click **Authorize** to request an authorization code. We will get the `client_id` and `client_secret` values from the 3scale application above. The `redirect_url` will be defined by the client application itself, and as such will already come pre-filled. The `scope` value defines the type of access requested. In this case it can be any string value and it will be displayed to the end user when they provide their consent.

The client application will then redirect the end user to the Authorization endpoint (as per [RFC6749#4.1.1](https://tools.ietf.org/html/rfc6749#section-4.1.1)), in this case the `/authorize` endpoint on our API Gateway instance: `localhost:8080/authorize`.

The end user should log in to the Authorization Server (our sample Authorization Server will accept any values for username and password) at which point they will be presented with a consent page to accept or deny the request for access.

The Authorization server will then either redirect back to APIcast (on `http://localhost:8080/callback`) to issue an authorization code on request acceptance or the application's `redirect_uri` directly on request denial. If the request is accepted, an authorization code will be issued (as per [RFC6749#4.1.2](https://tools.ietf.org/html/rfc6749#section-4.1.2)) by APIcast for the client.

This Authorization Code is sent to the client's Redirect URL (client callback endpoint on `http://localhost:3001/callback` in this case) and will be displayed at the sample client. We can then exchange this for an access token, by filling in our application's `client_secret`.

### Exchanging the Authorization Code for an Access Token

Once an authorization code is returned back to the sample client, you can exchange that for an access token by once again entering in the `client_id` additionally providing a `client_secret` and clicking **Get Token** to request an access token. At this point, the client application makes a request to the APIcast access token endpoint, in our case `http://localhost:8080/oauth/token`, sending the client credentials and Redirect URL along with the authorization code. APIcast will then validate these credentials and generate an access token with a fixed TTL of one week.

And that's it! We have now added OAuth Authorization Code Flow to our APIcast instance.
