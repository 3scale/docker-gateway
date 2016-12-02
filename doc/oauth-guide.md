# Using 3scale API Gateway with OAuth

## Pre-requisites

APICast offer support for the OAuth Authorization Code flow out of the box as long as the following pre-requisites are met:

- An Authorization Server as defined in [RFC6749#1.1](https://tools.ietf.org/html/rfc6749#section-1.1) with the one exception that the access tokens will be issued by APIcast instead. In this case the Authorization Server will only authenticate the resource owner and obtain their authorization.
- A Redis instance.

## APIcast Configuration in 3scale Admin Portal

In order to configure this, you will first need to choose the OAuth Authentication method from the Integration Settings (API > Integration > "edit integration settings" ) screen on your 3scale Admin portal. You will also need to ensure you have selected the Self Managed Gateway option, as it is not currently possible to run APIcast with OAuth Authorization Code support on the APIcast cloud gateway. 

Once that is done, you will see an additional field in the Integration Screen ( API > Integration ) under "Authentication Settings": "OAuth Authorization Endpoint." Here you will define where Resource Owners will be redirected to in order to authenticate and confirm they authorize a given client access to their resources ( as per [RFC6749#4.1](https://tools.ietf.org/html/rfc6749#section-4.1.1).) 

All other fields on the Integration Screen should be configured as per the "APIcast Overview" document. 

In order to show a sample integration with an Authorization Server we will use a very simple ruby app to act as an Authorization Server. This app will run on localhost port 3000 with the authorization endpoint at 


You can find the sample code for this app in the apicast/examples folder under oauth2. There you will also find a docker-compose file to allow you to deploy a test environment to test your API Integration and OAuth2 Authorization Code Flow. However, for the purposes of this document we will start every component locally from scratch.

## Testing the Flow

In order to test that all the moving pieces are correctly integrated we will use Postman to request an access token from APIcast. 





