# Mobile Connect GO library

[![Build Status](https://github.com/bertrandmartel/mobileconnect/workflows/test%20and%20build/badge.svg)](https://github.com/bertrandmartel/mobileconnect/actions?workflow=test%20and%20build)
[![Coverage Status](https://coveralls.io/repos/github/bertrandmartel/mobileconnect/badge.svg?branch=master)](https://coveralls.io/github/bertrandmartel/mobileconnect?branch=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/bertrandmartel/mobileconnect)](https://goreportcard.com/report/github.com/bertrandmartel/mobileconnect)
[![License](http://img.shields.io/:license-mit-blue.svg)](LICENSE.md)

Library written in GO implementing [Mobile Connect API](https://mobileconnect.io/) to be used by a Service Provider (SP).

## Existing Mobile Connect libraries

[GSMA](https://www.gsma.com) has released some open source libraries under https://github.com/Mobile-Connect, there are server side library written in Java, Php and .Net.

## Why this library ?

* discover how the protocol works from scratch (virtually all the calls are in `./sp/handlers/auth/auth.go`)
* provides an existing library written in Go
* provides instructions to work with https://mobileconnect.io sandbox
* provides a library that can be used with any Go web framework and any storage. The example in this repo uses [echo](https://github.com/labstack/echo) and [go-redis](https://github.com/go-redis/redis)

## What is Mobile Connect ?

Mobile Connect is an authentication/authorization protocol which prompts user with pin code / push button directly on their phone via the Mobile Network Operator. For this protocol to work, the Mobile operator needs to have implemented Mobile Connect protocol & the applet dedicated to the authentication must be present on the SIM card. [Some Mobile Network operators that have implemented Mobile connect](https://mobileconnect.io/about/#map)

## Flow

![architecture](https://user-images.githubusercontent.com/5183022/70481202-2726b280-1ae2-11ea-915c-1f6e3e26d69b.png)

Typically, according to https://mobileconnect.io, the flow is : 

* A user logs into the Service Provider website using a mobile connect button 
* The user is redirected to what is called the Api Exchange server (https://discovery.mobileconnect.io) with a page prompting the user for their MSISDN (aka phone number). Note that access to Api Exchange server is restricted by clientId/clientSecret provided by mobileconnect.io so, under the hood, the Service Provider redirects the user with those credentials
* The Api Exchange server checks the MSISDN, gets the matching mobile operator, gets the information about this mobile operator (API URL, credentials), send the following information back to the Service Provider platform :
  * Operator API URL (authorize API URL, tokens API URL, userinfo API URL)
  * Operator API clientID
  * encrypted MSISDN (the MSISDN is encrypted using Mobile Operator key)

* The Service Provider uses the [Mobile Connect API](https://developer.mobileconnect.io/authenticate-api) aka `/authorize` on the operator API URL (which was provided previously by the Api Exchange server). Along with this `/authorize` call, the following information are provided : 

  * the client ID for the Operator API provided previously by API Exchange server
  * the encrypted MSISDN provided previously by API Exchange server
  * the ACR values which corresponds to 
  [Level of Assurance Loa2/Loa3](https://developer.mobileconnect.io/level-of-assurance), Loa2 is No Pin, Loa3 is Pin code
  * the redirect URI which will be called by Operator platform when the user has been authenticated (eg when the user has pushed the button on the phone or set the Pin code depending on Loa2 or Lo3)

* The Mobile Operator platform redirects the user to a "waiting page" inviting the user to check his/her phone for push button/pin code
* When user push the button or types the pin code, the Mobile Operator platform sends a response back to the Service Provider using the previously provided redirect URI. If there is no error, the response comes with a `code` (authorization code flow)
* Using the `code`, the Service Provider call the [Get Tokens API](https://developer.mobileconnect.io/authenticate-api#tag/v1.1%2Fpaths%2F~1v1.1~1token_endpoint%2Fpost) to get the `access_token` and the `id_token`. The `access_token` will be used to access the user information (if provided by the operator), the `id_token` is a [JWT](https://jwt.io/) which contains a [PCR](https://developer.mobileconnect.io/the-pcr) which identifies a unique user by the mobile operator. This JWT comes with other claims that should be checked by the service provider server see [this](https://developer.mobileconnect.io/mc-tokens)
* Using the `access_token`, the service provider server gets the userinfo using the userinfo URL (not displayed on the image above)
* The service provider has authenticated the user & redirects to a logged in page (and store the user information in session)

The whole flow depicted above uses cookie to keep track of the user through the whole process

## Quick Start

You need to create an account on https://developer.mobileconnect.io to access the sandbox which is a testing environment where you can play with fake Mobile Operator and tests Mobile Connect API using this library

In "My Apps" https://developer.mobileconnect.io/myapps, create an app. It will generate credentials (clientID/clientSecret) to access the discovery page. This discovery server is the API Exchange server (see the flow section above)

You will need your server to be accessible by mobileconnect.io sandbox. To do this easily, download [ngrok](https://ngrok.com/) and in a shell, start a tunnel on port 6004 :

```bash
ngrok http 6004
```

In https://developer.mobileconnect.io/myapps add the callback URL with ngrok domain URL : 

![mcapp](https://user-images.githubusercontent.com/5183022/70481161-05c5c680-1ae2-11ea-8251-e392dd657f1e.png)

You need to edit `config-sandbox.json` with the discovery callback URL and the authorization callback URL : 

```
{
	"port": 6004,
	"serverPath": "http://localhost",
	"discoveryEndpoint": "https://discovery.sandbox.mobileconnect.io/v2/discovery",
	"authOptions": {
		"redirectUri": "https://XXXXXXXXX.ngrok.io/callback", <=== edit this with the correct ngrok subdomain
		"scope": "openid mc_authz mc_identity_signup",
		"version": "mc_di_r2_v2.3",
		"acr_values": "3",
		"client_name": "MCTesting",
		"binding_message": "some message",
		"context": "Login"
	},
	"client": {
		"client_id": "a0xxxxxxxxxxxxxxxxxxxxxxx36",  <======= edit this (provided by mobileconnect.io)
		"client_secret": "baxxxxxxxxxxxxxxxxxxxxxxxxxx3f", <==== edit this (provided by mobileconnect.io)
		"redirect_uri": [
			"https://XXXXXXXXX.ngrok.io/discovery_callback" <=== edit this with the correct ngrok subdomain
		]
	}
}
```

Run the server : 

```bash
go run ./example/main.go
```

Go to http://localhost:6004/login, you will need to enter the MSISDN for an operator. In the sandbox see the MSISDN list : https://developer.mobileconnect.io/the-sandbox#test-operators for instance +447700900301

## Testing

```bash
go test -coverprofile=coverage.out  ./sp/...
go tool cover -html=coverage.out
```

## Dependencies

* Library
  * https://github.com/dgrijalva/jwt-go
  * https://github.com/lestrrat-go/jwx
  * https://github.com/satori/go.uuid

* Example
  * https://github.com/labstack/echo
  * https://github.com/go-redis/redis