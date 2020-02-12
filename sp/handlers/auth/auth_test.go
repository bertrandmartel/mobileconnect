package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/bertrandmartel/mobileconnect/sp/application"
	"github.com/bertrandmartel/mobileconnect/sp/config"
	"github.com/bertrandmartel/mobileconnect/sp/mcmodel"
	"github.com/bertrandmartel/mobileconnect/sp/session"
	"github.com/stretchr/testify/assert"
)

var httpClient = &http.Client{
	Timeout: 10 * time.Second,
}

var globalConfig = &config.Config{
	Version:           "0.1",
	Port:              6004,
	ServerPath:        "http://localhost",
	DiscoveryEndpoint: "https://discovery.sandbox.mobileconnect.io/v2/discovery",
	AuthOptions: config.AuthOptions{
		RedirectURI:         "http://localhost:6004/callback",
		Scope:               "openid mc_authz mc_identity_signup",
		Version:             "mc_di_r2_v2.3",
		AcrValues:           "3",
		ClientName:          "MCTesting",
		BindingMessage:      "some message",
		Context:             "Login",
		JwtVerificationSkip: []string{"nonce", "acr"},
	},
	Client: config.Client{
		ClientID:     "client_id_for_discoverty",
		ClientSecret: "client_secret_for_discoverty",
		RedirectURI:  []string{"http://localhost:6004/discovery_callback"},
	},
}

const testingServerBaseURL = "http://localhost:3132"
const discoveryURL = "http://localhost/discovery-ui"
const authorizeURL = "http://localhost/authorize"
const tokenURL = "http://localhost/token"
const userinfoURL = "http://localhost/userinfo"

var sharedParams = &SharedAppParams{}

var httpServer http.Server

var mccMncDiscoveryResponse = &mcmodel.MccMncDiscoveryResponse{
	TTL: 1518882158,
	Response: mcmodel.OperatorConfig{
		ClientID:        "some client id",
		ClientSecret:    "some client secret",
		ServingOperator: "operator A",
		Country:         "France",
		Currency:        "Euro",
		Apis: mcmodel.IDGatewayAPI{
			OperatorID: mcmodel.IDGatewayOperatorMeta{
				Link: []mcmodel.IDGatewayOperatorLink{
					{
						Rel:  "authorization",
						Href: authorizeURL,
					},
					{
						Rel:  "token",
						Href: tokenURL,
					},
					{
						Rel:  "premiuminfo",
						Href: userinfoURL,
					},
				},
			},
		},
	},
}

var tokenResponse = &mcmodel.TokenResponse{
	AccessToken:   "some access token",
	TokenType:     "Bearer",
	ExpiresIn:     100,
	IDToken:       "some jwt token",
	CorrelationID: "some correlation id",
}

var userInfoResponse = &mcmodel.UserInfoResponse{
	Sub:                  "PCR",
	PhoneNumberAlternate: "0123456789",
	Title:                "M",
	GivenName:            "John Doe",
	FamilyName:           "Doe",
	MiddleName:           "",
	StreetAddress:        "10 downing street",
	City:                 "London",
	State:                "London",
	PostalCode:           "ABCD",
	Country:              "UK",
	Email:                "john@example.com",
}

var discoveryResponse = &mcmodel.DiscoveryResponse{
	Links: []mcmodel.IDGatewayOperatorLink{
		{
			Rel:  "operatorSelection",
			Href: discoveryURL,
		},
	},
}

func startHTTPServer() {
	httpServer := &http.Server{Addr: ":3132"}

	http.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello world\n")
	})
	http.HandleFunc("/401", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "401 Unauthorized", http.StatusUnauthorized)
	})
	http.HandleFunc("/405", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "405 Not Allowed", http.StatusMethodNotAllowed)
	})
	http.HandleFunc("/discovery_response", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(discoveryResponse)
	})
	http.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(tokenResponse)
	})
	http.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(userInfoResponse)
	})
	http.HandleFunc("/discovery", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(mccMncDiscoveryResponse)
	})

	go func() {
		if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
			fmt.Println(fmt.Sprintf("ListenAndServe(): %s", err))
		}
	}()
}

func setup() {
	fmt.Println("launching testing http server")
	startHTTPServer()
	time.Sleep(1 * time.Second)
}

func shutdown() {
	fmt.Println("shutdown")
	if err := httpServer.Shutdown(context.Background()); err != nil {
		fmt.Println(err)
	}
}

//executed before all test in this package
func TestMain(m *testing.M) {
	setup()
	code := m.Run()
	shutdown()
	os.Exit(code)
}

type SharedAppParams struct {
	Context      interface{}
	Session      *session.Session
	Error        error
	SetSession   *session.Session
	Location     *string
	LoginSuccess bool
	CookieName   string
	CookieValue  string
	Redirect     bool
}

type TestMessage struct {
	UserID    int    `json:"userId"`
	ID        int    `json:"id"`
	Title     string `json:"title"`
	Completed bool   `json:"completed"`
}

func TestFetchDiscovery(t *testing.T) {
	//no http client
	err := fetchDiscovery(nil, "http://google.com/test", nil, "", "")
	assert.NotNil(t, err)
	assert.Equal(t, "no http client specified", err.Error())

	//here the request endup in error after Do
	err = fetchDiscovery(httpClient, "", nil, "", "")
	assert.NotNil(t, err)

	//404
	err = fetchDiscovery(httpClient, fmt.Sprintf("%v/404", testingServerBaseURL), nil, "", "")
	assert.NotNil(t, err)
	assert.Equal(t, "record was not found", err.Error())

	//incorrect status code
	err = fetchDiscovery(httpClient, fmt.Sprintf("%v/hello", testingServerBaseURL), nil, "", "")
	assert.NotNil(t, err)
	assert.Equal(t, "received incorrect status : 200", err.Error())

	//request valid but status code not the one expected
	discoveryResponse := new(mcmodel.DiscoveryResponse)
	err = fetchDiscovery(httpClient, fmt.Sprintf("%v/discovery_response", testingServerBaseURL), discoveryResponse, "", "")
	assert.Nil(t, err)
	assert.Equal(t, 1, len(discoveryResponse.Links))
	assert.Equal(t, discoveryURL, discoveryResponse.Links[0].Href)
	assert.Equal(t, "operatorSelection", discoveryResponse.Links[0].Rel)
}

func TestFetchOperator(t *testing.T) {
	//no http client
	err := fetchOperator(nil, globalConfig, nil, []string{})
	assert.NotNil(t, err)
	assert.Equal(t, "no http client specified", err.Error())

	//no config
	err = fetchOperator(httpClient, nil, nil, []string{})
	assert.NotNil(t, err)
	assert.Equal(t, "no config specified", err.Error())

	//mcc/mnc empty
	err = fetchOperator(httpClient, globalConfig, nil, []string{})
	assert.NotNil(t, err)
	assert.Equal(t, "wrong mcc mnc value", err.Error())

	//here the request endup in error after Do
	globalConfig.DiscoveryEndpoint = ""
	err = fetchOperator(httpClient, globalConfig, nil, []string{"302", "22"})
	assert.NotNil(t, err)

	//404
	globalConfig.DiscoveryEndpoint = fmt.Sprintf("%v/404", testingServerBaseURL)
	err = fetchOperator(httpClient, globalConfig, nil, []string{"302", "22"})
	assert.NotNil(t, err)
	assert.Equal(t, "record was not found", err.Error())

	//!=404 & !=200
	globalConfig.DiscoveryEndpoint = fmt.Sprintf("%v/401", testingServerBaseURL)
	err = fetchOperator(httpClient, globalConfig, nil, []string{"302", "22"})
	assert.NotNil(t, err)
	assert.Equal(t, "received incorrect status : 401", err.Error())

	//200 but JSON error
	globalConfig.DiscoveryEndpoint = fmt.Sprintf("%v/hello", testingServerBaseURL)
	err = fetchOperator(httpClient, globalConfig, nil, []string{"302", "22"})
	assert.NotNil(t, err)

	//OK
	globalConfig.DiscoveryEndpoint = fmt.Sprintf("%v/discovery", testingServerBaseURL)
	resp := new(mcmodel.MccMncDiscoveryResponse)
	err = fetchOperator(httpClient, globalConfig, resp, []string{"302", "22"})
	assert.Nil(t, err)
	assert.Equal(t, mccMncDiscoveryResponse.TTL, resp.TTL)
	assert.Equal(t, mccMncDiscoveryResponse.Response.ClientID, resp.Response.ClientID)
	assert.Equal(t, mccMncDiscoveryResponse.Response.ClientSecret, resp.Response.ClientSecret)
	assert.Equal(t, mccMncDiscoveryResponse.Response.ServingOperator, resp.Response.ServingOperator)
	assert.Equal(t, mccMncDiscoveryResponse.Response.Country, resp.Response.Country)
	assert.Equal(t, mccMncDiscoveryResponse.Response.Currency, resp.Response.Currency)
}

func TestFetchToken(t *testing.T) {
	//no http client
	err := fetchToken(nil, "", nil, "", "", "")
	assert.NotNil(t, err)
	assert.Equal(t, "no http client specified", err.Error())

	//no url
	err = fetchToken(httpClient, "", nil, "", "", "")
	assert.NotNil(t, err)

	//404
	err = fetchToken(httpClient, fmt.Sprintf("%v/404", testingServerBaseURL), nil, "", "", "")
	assert.NotNil(t, err)
	assert.Equal(t, "record was not found", err.Error())

	//!=200 & !=404
	err = fetchToken(httpClient, fmt.Sprintf("%v/405", testingServerBaseURL), nil, "", "", "")
	assert.NotNil(t, err)
	assert.Equal(t, "received incorrect status : 405", err.Error())

	//OK
	resp := new(mcmodel.TokenResponse)
	err = fetchToken(httpClient, fmt.Sprintf("%v/token", testingServerBaseURL), resp, "", "", "")
	assert.Nil(t, err)
	assert.Equal(t, tokenResponse.AccessToken, resp.AccessToken)
	assert.Equal(t, tokenResponse.TokenType, resp.TokenType)
	assert.Equal(t, fmt.Sprintf("%v", tokenResponse.ExpiresIn), fmt.Sprintf("%v", resp.ExpiresIn))
	assert.Equal(t, tokenResponse.IDToken, resp.IDToken)
	assert.Equal(t, tokenResponse.CorrelationID, resp.CorrelationID)
}

func TestFetchUserInfo(t *testing.T) {
	//no http client
	err := fetchUserInfo(nil, "", nil, "")
	assert.NotNil(t, err)
	assert.Equal(t, "no http client specified", err.Error())

	//no url
	err = fetchUserInfo(httpClient, "", nil, "")
	assert.NotNil(t, err)

	//404
	err = fetchUserInfo(httpClient, fmt.Sprintf("%v/404", testingServerBaseURL), nil, "")
	assert.NotNil(t, err)
	assert.Equal(t, "record was not found", err.Error())

	//!=404 & !=200
	err = fetchUserInfo(httpClient, fmt.Sprintf("%v/401", testingServerBaseURL), nil, "")
	assert.NotNil(t, err)
	assert.Equal(t, "received incorrect status : 401", err.Error())

	//200 but JSON error
	err = fetchUserInfo(httpClient, fmt.Sprintf("%v/hello", testingServerBaseURL), nil, "")
	assert.NotNil(t, err)

	//OK
	resp := new(mcmodel.UserInfoResponse)
	err = fetchUserInfo(httpClient, fmt.Sprintf("%v/userinfo", testingServerBaseURL), resp, "")
	assert.Nil(t, err)
	assert.Equal(t, userInfoResponse.Sub, resp.Sub)
	assert.Equal(t, userInfoResponse.PhoneNumberAlternate, resp.PhoneNumberAlternate)
	assert.Equal(t, userInfoResponse.Title, resp.Title)
	assert.Equal(t, userInfoResponse.GivenName, resp.GivenName)
	assert.Equal(t, userInfoResponse.FamilyName, resp.FamilyName)
	assert.Equal(t, userInfoResponse.MiddleName, resp.MiddleName)
	assert.Equal(t, userInfoResponse.StreetAddress, resp.StreetAddress)
	assert.Equal(t, userInfoResponse.City, resp.City)
	assert.Equal(t, userInfoResponse.State, resp.State)
	assert.Equal(t, userInfoResponse.PostalCode, resp.PostalCode)
	assert.Equal(t, userInfoResponse.Country, resp.Country)
	assert.Equal(t, userInfoResponse.Email, resp.Email)
}

func TestAuthorize(t *testing.T) {
	operatorConfig := &mcmodel.OperatorConfig{
		ClientID:        "some client id",
		ClientSecret:    "",
		ServingOperator: "",
		Country:         "",
		Currency:        "",
		Apis: mcmodel.IDGatewayAPI{
			OperatorID: mcmodel.IDGatewayOperatorMeta{
				Link: []mcmodel.IDGatewayOperatorLink{
					{
						Href: "test",
						Rel:  "test",
					},
				},
			},
		},
	}
	//operator config nil
	auhtorizeURL, err := authorize(nil, globalConfig, "", "", "")
	assert.Equal(t, "", auhtorizeURL)
	assert.NotNil(t, err)
	assert.Equal(t, "operatorConfig is nil", err.Error())

	//config nil
	auhtorizeURL, err = authorize(operatorConfig, nil, "", "", "")
	assert.Equal(t, "", auhtorizeURL)
	assert.NotNil(t, err)
	assert.Equal(t, "config is nil", err.Error())

	//auhorization url missing
	auhtorizeURL, err = authorize(operatorConfig, globalConfig, "", "", "")
	assert.Equal(t, "", auhtorizeURL)
	assert.NotNil(t, err)
	assert.Equal(t, "authorization url not found", err.Error())

	operatorConfig.Apis.OperatorID.Link[0].Rel = "authorization"
	operatorConfig.Apis.OperatorID.Link[0].Href = "http://localhost"
	auhtorizeURL, err = authorize(operatorConfig, globalConfig, "some state", "some subscriberId", "some nonce")
	assert.Nil(t, err)
	u, err := url.Parse(auhtorizeURL)
	assert.Nil(t, err)
	q := u.Query()
	assert.Equal(t, operatorConfig.ClientID, q.Get("client_id"))
	assert.Equal(t, globalConfig.AuthOptions.RedirectURI, q.Get("redirect_uri"))
	assert.Equal(t, "code", q.Get("response_type"))
	assert.Equal(t, globalConfig.AuthOptions.Scope, q.Get("scope"))
	assert.Equal(t, globalConfig.AuthOptions.Version, q.Get("version"))
	assert.Equal(t, "some state", q.Get("state"))
	assert.Equal(t, "some nonce", q.Get("nonce"))
	assert.Equal(t, "ENCR_MSISDN:some subscriberId", q.Get("login_hint"))
	assert.Equal(t, globalConfig.AuthOptions.AcrValues, q.Get("acr_values"))
	assert.Equal(t, globalConfig.AuthOptions.ClientName, q.Get("client_name"))
	assert.Equal(t, globalConfig.AuthOptions.BindingMessage, q.Get("binding_message"))
	assert.Equal(t, globalConfig.AuthOptions.Context, q.Get("context"))
}

func TestAuthorizeWithPCR(t *testing.T) {
	s := &session.Session{
		ID:                "some id",
		Nonce:             "some nonce",
		AuthorizeEndpoint: "",
		OperatorConfig: mcmodel.OperatorConfig{
			ClientID:        "some client id",
			ClientSecret:    "",
			ServingOperator: "",
			Country:         "",
			Currency:        "",
			Apis: mcmodel.IDGatewayAPI{
				OperatorID: mcmodel.IDGatewayOperatorMeta{
					Link: []mcmodel.IDGatewayOperatorLink{
						{
							Href: "test",
							Rel:  "test",
						},
					},
				},
			},
		},
		UserInfo: mcmodel.UserInfoResponse{
			Sub: "some subscriberId",
		},
	}
	//config nil
	auhtorizeURL, err := authorizeWithPCR(nil, s, false)
	assert.Equal(t, "", auhtorizeURL)
	assert.NotNil(t, err)
	assert.Equal(t, "config is nil", err.Error())

	//session nil
	auhtorizeURL, err = authorizeWithPCR(globalConfig, nil, false)
	assert.Equal(t, "", auhtorizeURL)
	assert.NotNil(t, err)
	assert.Equal(t, "session is nil", err.Error())

	//authorization url missing
	s.AuthorizeEndpoint = ""
	auhtorizeURL, err = authorizeWithPCR(globalConfig, s, false)
	assert.Equal(t, "", auhtorizeURL)
	assert.NotNil(t, err)
	assert.Equal(t, "authorization url not found", err.Error())

	//PCR false
	s.AuthorizeEndpoint = "http://localhost"
	auhtorizeURL, err = authorizeWithPCR(globalConfig, s, false)
	assert.Nil(t, err)
	u, err := url.Parse(auhtorizeURL)
	assert.Nil(t, err)
	q := u.Query()
	assert.Equal(t, s.OperatorConfig.ClientID, q.Get("client_id"))
	assert.Equal(t, globalConfig.AuthOptions.RedirectURI, q.Get("redirect_uri"))
	assert.Equal(t, "code", q.Get("response_type"))
	assert.Equal(t, globalConfig.AuthOptions.Scope, q.Get("scope"))
	assert.Equal(t, globalConfig.AuthOptions.Version, q.Get("version"))
	assert.Equal(t, s.ID, q.Get("state"))
	assert.Equal(t, s.Nonce, q.Get("nonce"))
	assert.Equal(t, s.UserInfo.Sub, q.Get("login_hint"))
	assert.Equal(t, globalConfig.AuthOptions.AcrValues, q.Get("acr_values"))
	assert.Equal(t, globalConfig.AuthOptions.ClientName, q.Get("client_name"))
	assert.Equal(t, globalConfig.AuthOptions.BindingMessage, q.Get("binding_message"))
	assert.Equal(t, globalConfig.AuthOptions.Context, q.Get("context"))

	//PCR true
	s.AuthorizeEndpoint = "http://localhost"
	auhtorizeURL, err = authorizeWithPCR(globalConfig, s, true)
	assert.Nil(t, err)
	u, err = url.Parse(auhtorizeURL)
	assert.Nil(t, err)
	q = u.Query()
	assert.Equal(t, s.OperatorConfig.ClientID, q.Get("client_id"))
	assert.Equal(t, globalConfig.AuthOptions.RedirectURI, q.Get("redirect_uri"))
	assert.Equal(t, "code", q.Get("response_type"))
	assert.Equal(t, globalConfig.AuthOptions.Scope, q.Get("scope"))
	assert.Equal(t, globalConfig.AuthOptions.Version, q.Get("version"))
	assert.Equal(t, s.ID, q.Get("state"))
	assert.Equal(t, s.Nonce, q.Get("nonce"))
	assert.Equal(t, "PCR:"+s.UserInfo.Sub, q.Get("login_hint"))
	assert.Equal(t, globalConfig.AuthOptions.AcrValues, q.Get("acr_values"))
	assert.Equal(t, globalConfig.AuthOptions.ClientName, q.Get("client_name"))
	assert.Equal(t, globalConfig.AuthOptions.BindingMessage, q.Get("binding_message"))
	assert.Equal(t, globalConfig.AuthOptions.Context, q.Get("context"))
}

func TestRenderFailedLogin(t *testing.T) {
	//app nil
	err := renderFailedLogin(nil, "", nil, nil)
	assert.NotNil(t, err)
	assert.Equal(t, "app is nil", err.Error())

	var mcHandler application.MobileConnectApp = &CustomMcApp{}
	s := &session.Session{
		ErrorMessage: "",
	}
	//session is nil
	err = renderFailedLogin(nil, "test", &mcHandler, nil)
	assert.NotNil(t, err)
	assert.Equal(t, "session is nil", err.Error())

	//message empty
	clearSharedParam()
	sharedParams.Error = errors.New("some custom error")
	s.ErrorMessage = "some error"
	testContext := &TestMessage{
		UserID: 1,
	}
	err = renderFailedLogin(testContext, "", &mcHandler, s)
	assert.NotNil(t, err)
	assert.Equal(t, "some custom error", err.Error())
	assert.NotNil(t, sharedParams.Context)
	mess := sharedParams.Context.(*TestMessage)
	assert.Equal(t, 1, mess.UserID)
	assert.NotNil(t, sharedParams.Session)
	assert.Equal(t, "some error", sharedParams.Session.ErrorMessage)
	assert.Nil(t, sharedParams.SetSession)

	clearSharedParam()
	sharedParams.Error = errors.New("some custom error")
	s.ErrorMessage = "some error"
	testContext = &TestMessage{
		UserID: 1,
	}
	err = renderFailedLogin(testContext, "another error", &mcHandler, s)
	assert.NotNil(t, err)
	assert.Equal(t, "some custom error", err.Error())
	assert.NotNil(t, sharedParams.Context)
	mess = sharedParams.Context.(*TestMessage)
	assert.Equal(t, 1, mess.UserID)
	assert.NotNil(t, sharedParams.Session)
	assert.Equal(t, "another error", sharedParams.Session.ErrorMessage)
	assert.NotNil(t, sharedParams.SetSession)
	assert.Equal(t, "another error", sharedParams.SetSession.ErrorMessage)
}

func TestSearchLinkField(t *testing.T) {
	operatorConfig := &mcmodel.OperatorConfig{
		ClientID:        "some client id",
		ClientSecret:    "",
		ServingOperator: "",
		Country:         "",
		Currency:        "",
		Apis: mcmodel.IDGatewayAPI{
			OperatorID: mcmodel.IDGatewayOperatorMeta{
				Link: []mcmodel.IDGatewayOperatorLink{
					{
						Href: "http://localhost",
						Rel:  "test",
					},
				},
			},
		},
	}
	//operatorConfig nil
	result := searchLinkField(nil, "")
	assert.Equal(t, "", result)

	result = searchLinkField(&operatorConfig.Apis.OperatorID.Link, "")
	assert.Equal(t, "", result)

	result = searchLinkField(&operatorConfig.Apis.OperatorID.Link, "test")
	assert.Equal(t, "http://localhost", result)
}

func TestProcess(t *testing.T) {
	var mcHandler application.MobileConnectApp = &CustomMcApp{}
	s := &session.Session{
		ErrorMessage: "",
	}
	request := &mcmodel.DiscoveryRequest{
		SubscriberID: "subid",
		MccMnc:       "302_22",
		ErrorMessage: "error message",
	}
	//request nil
	clearSharedParam()
	err := Process(nil, nil, mcHandler, s)
	assert.Nil(t, err)
	assert.Equal(t, "request is nil", s.ErrorMessage)
	assert.Equal(t, "request is nil", sharedParams.Session.ErrorMessage)

	//session nil
	clearSharedParam()
	err = Process(nil, request, mcHandler, nil)
	assert.NotNil(t, err)
	assert.Equal(t, "session is nil", err.Error())

	//request.ErrorMessage not empty with error message NotSupportedOperatorMSISDN
	clearSharedParam()
	request.ErrorMessage = "NotSupportedOperatorMSISDN"
	err = Process(nil, request, mcHandler, s)
	assert.Nil(t, err)
	assert.Equal(t, "Operator for this phone number was not found", s.ErrorMessage)
	assert.Equal(t, "Operator for this phone number was not found", sharedParams.Session.ErrorMessage)

	//request.ErrorMessage not empty with error message MSISDNNotFound
	clearSharedParam()
	request.ErrorMessage = "MSISDNNotFound"
	err = Process(nil, request, mcHandler, s)
	assert.Nil(t, err)
	assert.Equal(t, "Mobile Connect is not supported for this phone number", s.ErrorMessage)
	assert.Equal(t, "Mobile Connect is not supported for this phone number", sharedParams.Session.ErrorMessage)

	//request.ErrorMessage not empty with error message custom
	clearSharedParam()
	request.ErrorMessage = "custom error message"
	err = Process(nil, request, mcHandler, s)
	assert.Nil(t, err)
	assert.Equal(t, "custom error message", s.ErrorMessage)
	assert.Equal(t, "custom error message", sharedParams.Session.ErrorMessage)

	//request.SubscriberID or request.MccMnc is empty
	clearSharedParam()
	request.ErrorMessage = ""
	request.SubscriberID = ""
	err = Process(nil, request, mcHandler, s)
	assert.Nil(t, err)
	assert.Equal(t, "ApiExchange failed to send required parameters", s.ErrorMessage)
	assert.Equal(t, "ApiExchange failed to send required parameters", sharedParams.Session.ErrorMessage)

	//mccMnc format is wrong
	clearSharedParam()
	request.ErrorMessage = ""
	request.SubscriberID = "SubId"
	request.MccMnc = "30222"
	err = Process(nil, request, mcHandler, s)
	assert.Nil(t, err)
	assert.Equal(t, "Bad MCC/MNC format", s.ErrorMessage)
	assert.Equal(t, "Bad MCC/MNC format", sharedParams.Session.ErrorMessage)

	//config.DiscoveryEndpoint is incorrect
	globalConfig.DiscoveryEndpoint = ""
	clearSharedParam()
	request.ErrorMessage = ""
	request.SubscriberID = "SubId"
	request.MccMnc = "302_22"
	err = Process(nil, request, mcHandler, s)
	assert.Nil(t, err)
	assert.Equal(t, "Fail to find operator", s.ErrorMessage)
	assert.Equal(t, "Fail to find operator", sharedParams.Session.ErrorMessage)

	//config.DiscoveryEndpoint is correct but authorization URL is empty
	globalConfig.DiscoveryEndpoint = fmt.Sprintf("%v/discovery", testingServerBaseURL)
	clearSharedParam()
	request.ErrorMessage = ""
	request.SubscriberID = "SubId"
	request.MccMnc = "302_22"
	s.OperatorConfig = mcmodel.OperatorConfig{
		ClientID:        "",
		ClientSecret:    "",
		ServingOperator: "",
		Country:         "",
		Currency:        "",
	}
	mccMncDiscoveryResponse.Response.Apis.OperatorID.Link = []mcmodel.IDGatewayOperatorLink{}
	err = Process(nil, request, mcHandler, s)
	assert.Nil(t, err)
	assert.Equal(t, "authorization url not found", s.ErrorMessage)
	assert.Equal(t, "authorization url not found", sharedParams.Session.ErrorMessage)
	assert.Equal(t, mccMncDiscoveryResponse.Response.ClientID, s.OperatorConfig.ClientID)
	assert.Equal(t, mccMncDiscoveryResponse.Response.ClientSecret, s.OperatorConfig.ClientSecret)
	assert.Equal(t, mccMncDiscoveryResponse.Response.ServingOperator, s.OperatorConfig.ServingOperator)
	assert.Equal(t, mccMncDiscoveryResponse.Response.Country, s.OperatorConfig.Country)
	assert.Equal(t, mccMncDiscoveryResponse.Response.Currency, s.OperatorConfig.Currency)

	//OK
	globalConfig.DiscoveryEndpoint = fmt.Sprintf("%v/discovery", testingServerBaseURL)
	clearSharedParam()
	request.ErrorMessage = ""
	request.SubscriberID = "SubId"
	request.MccMnc = "302_22"
	s.OperatorConfig = mcmodel.OperatorConfig{
		ClientID:        "",
		ClientSecret:    "",
		ServingOperator: "",
		Country:         "",
		Currency:        "",
	}
	s.ErrorMessage = ""
	mccMncDiscoveryResponse.Response.Apis.OperatorID.Link = []mcmodel.IDGatewayOperatorLink{
		{
			Rel:  "authorization",
			Href: authorizeURL,
		},
		{
			Rel:  "token",
			Href: tokenURL,
		},
		{
			Rel:  "premiuminfo",
			Href: userinfoURL,
		},
	}
	err = Process(nil, request, mcHandler, s)
	assert.Nil(t, err)
	assert.Equal(t, "", s.ErrorMessage)
	assert.Equal(t, mccMncDiscoveryResponse.Response.ClientID, s.OperatorConfig.ClientID)
	assert.Equal(t, mccMncDiscoveryResponse.Response.ClientSecret, s.OperatorConfig.ClientSecret)
	assert.Equal(t, mccMncDiscoveryResponse.Response.ServingOperator, s.OperatorConfig.ServingOperator)
	assert.Equal(t, mccMncDiscoveryResponse.Response.Country, s.OperatorConfig.Country)
	assert.Equal(t, mccMncDiscoveryResponse.Response.Currency, s.OperatorConfig.Currency)
	assert.NotNil(t, sharedParams.Location)
	location, err := authorize(&mccMncDiscoveryResponse.Response, globalConfig, s.ID, request.SubscriberID, s.Nonce)
	assert.Nil(t, err)
	assert.Equal(t, location, *sharedParams.Location)
}

func TestCallback(t *testing.T) {
	var mcHandler application.MobileConnectApp = &CustomMcApp{}
	request := &mcmodel.LoginCallback{
		Error:            "some error",
		ErrorDescription: "some error description",
		Code:             "code",
		State:            "state",
	}
	//request nil
	clearSharedParam()
	err := Callback(nil, nil, mcHandler)
	assert.NotNil(t, err)
	assert.Equal(t, "session is nil", err.Error())

	//request.Error not empty
	request.Error = "some error"
	request.ErrorDescription = "some error description"
	clearSharedParam()
	err = Callback(nil, request, mcHandler)
	assert.Nil(t, err)
	fmt.Println(err)
	assert.Equal(t, request.Error+" : "+request.ErrorDescription, sharedParams.SetSession.ErrorMessage)

	//code is empty
	request.Error = ""
	request.ErrorDescription = ""
	request.Code = ""
	clearSharedParam()
	err = Callback(nil, request, mcHandler)
	assert.Nil(t, err)
	/*
	request.Code = "code"

	s.OperatorConfig = mcmodel.OperatorConfig{
		Apis: mcmodel.IDGatewayAPI{
			OperatorID: mcmodel.IDGatewayOperatorMeta{
				Link: []mcmodel.IDGatewayOperatorLink{
					{
						Href: "http://localhost",
						Rel:  "test",
					},
				},
			},
		},
	}
	//token endpoint is not in operator config

	clearSharedParam()
	err = Callback(nil, request, mcHandler)
	assert.Nil(t, err)
	assert.Equal(t, "token endpoint not found in operator config", sharedParams.SetSession.ErrorMessage)

	s.OperatorConfig.Apis.OperatorID.Link = append(
		s.OperatorConfig.Apis.OperatorID.Link,
		mcmodel.IDGatewayOperatorLink{
			Href: fmt.Sprintf("%v/token_incorrect_url", testingServerBaseURL),
			Rel:  "token",
		})

	//userinfo endpoint is not in operator config
	clearSharedParam()
	err = Callback(nil, request, mcHandler, s)
	assert.Nil(t, err)
	assert.Equal(t, "premiuminfo endpoint not found in operator config", s.ErrorMessage)
	assert.Equal(t, "premiuminfo endpoint not found in operator config", sharedParams.Session.ErrorMessage)

	s.OperatorConfig.Apis.OperatorID.Link = append(
		s.OperatorConfig.Apis.OperatorID.Link,
		mcmodel.IDGatewayOperatorLink{
			Href: fmt.Sprintf("%v/userinfo_incorrect_url", testingServerBaseURL),
			Rel:  "premiuminfo",
		})

	//token endpoint is in config but is incorrect
	clearSharedParam()
	err = Callback(nil, request, mcHandler, s)
	assert.Nil(t, err)
	assert.Equal(t, "Fail to get token", s.ErrorMessage)
	assert.Equal(t, "Fail to get token", sharedParams.Session.ErrorMessage)

	s.OperatorConfig.Apis.OperatorID.Link = []mcmodel.IDGatewayOperatorLink{
		{
			Href: fmt.Sprintf("%v/token", testingServerBaseURL),
			Rel:  "token",
		}, {
			Href: fmt.Sprintf("%v/userinfo_incorrect_url", testingServerBaseURL),
			Rel:  "premiuminfo",
		},
	}

	//userinfo endpoint is in config but is incorrect
	clearSharedParam()
	err = Callback(nil, request, mcHandler, s)
	assert.Nil(t, err)
	assert.Equal(t, "Fail to get userinfo", s.ErrorMessage)
	assert.Equal(t, "Fail to get userinfo", sharedParams.Session.ErrorMessage)

	s.OperatorConfig.Apis.OperatorID.Link = []mcmodel.IDGatewayOperatorLink{
		{
			Href: fmt.Sprintf("%v/token", testingServerBaseURL),
			Rel:  "token",
		}, {
			Href: fmt.Sprintf("%v/userinfo", testingServerBaseURL),
			Rel:  "premiuminfo",
		},
	}

	//jwks endpoint is not in config
	clearSharedParam()
	err = Callback(nil, request, mcHandler, s)
	assert.Nil(t, err)
	assert.Equal(t, "jwks endpoint not found in operator config", s.ErrorMessage)
	assert.Equal(t, "jwks endpoint not found in operator config", sharedParams.Session.ErrorMessage)

	s.OperatorConfig.Apis.OperatorID.Link = append(
		s.OperatorConfig.Apis.OperatorID.Link,
		mcmodel.IDGatewayOperatorLink{
			Href: fmt.Sprintf("%v/jwks", testingServerBaseURL),
			Rel:  "jwks",
		})

	//authorization endpoint is not in config
	clearSharedParam()
	err = Callback(nil, request, mcHandler, s)
	assert.Nil(t, err)
	assert.Equal(t, "authorization endpoint not found in operator config", s.ErrorMessage)
	assert.Equal(t, "authorization endpoint not found in operator config", sharedParams.Session.ErrorMessage)

	s.OperatorConfig.Apis.OperatorID.Link = append(
		s.OperatorConfig.Apis.OperatorID.Link,
		mcmodel.IDGatewayOperatorLink{
			Href: fmt.Sprintf("%v/authorize", testingServerBaseURL),
			Rel:  "authorization",
		})

	//issuer value is not in config
	clearSharedParam()
	err = Callback(nil, request, mcHandler, s)
	assert.Nil(t, err)
	assert.Equal(t, "issuer value not found in operator config", s.ErrorMessage)
	assert.Equal(t, "issuer value not found in operator config", sharedParams.Session.ErrorMessage)

	s.OperatorConfig.Apis.OperatorID.Link = append(
		s.OperatorConfig.Apis.OperatorID.Link,
		mcmodel.IDGatewayOperatorLink{
			Href: "http://localhost",
			Rel:  "issuer",
		})

	//OK
	clearSharedParam()
	s.UserInfo = mcmodel.UserInfoResponse{}
	err = Callback(nil, request, mcHandler, s)
	assert.Nil(t, err)
	assert.Equal(t, userInfoResponse.Sub, s.UserInfo.Sub)
	assert.Equal(t, userInfoResponse.PhoneNumberAlternate, s.UserInfo.PhoneNumberAlternate)
	assert.Equal(t, userInfoResponse.Title, s.UserInfo.Title)
	assert.Equal(t, userInfoResponse.GivenName, s.UserInfo.GivenName)
	assert.Equal(t, userInfoResponse.FamilyName, s.UserInfo.FamilyName)
	assert.Equal(t, userInfoResponse.MiddleName, s.UserInfo.MiddleName)
	assert.Equal(t, userInfoResponse.StreetAddress, s.UserInfo.StreetAddress)
	assert.Equal(t, userInfoResponse.City, s.UserInfo.City)
	assert.Equal(t, userInfoResponse.State, s.UserInfo.State)
	assert.Equal(t, userInfoResponse.PostalCode, s.UserInfo.PostalCode)
	assert.Equal(t, userInfoResponse.Email, s.UserInfo.Email)

	assert.True(t, sharedParams.LoginSuccess)
	assert.Equal(t, sharedParams.CookieName, session.JWTCookie)
	assert.Equal(t, sharedParams.CookieValue, tokenResponse.IDToken)
	*/
}

func TestAuthentication(t *testing.T) {
	var mcHandler application.MobileConnectApp = &CustomMcApp{}
	s := &session.Session{
		ErrorMessage: "",
	}

	//session is nil
	clearSharedParam()
	err := Authentication(nil, mcHandler, nil)
	assert.NotNil(t, err)
	assert.Equal(t, "session is nil", err.Error())

	//s.UserInfo.Sub is empty, discovery endpoint is empty
	clearSharedParam()
	globalConfig.DiscoveryEndpoint = ""
	err = Authentication(nil, mcHandler, s)
	assert.Nil(t, err)
	assert.Equal(t, "Fail to initiate session with ApiExchange", s.ErrorMessage)
	assert.Equal(t, "Fail to initiate session with ApiExchange", sharedParams.Session.ErrorMessage)

	//s.UserInfo.Sub is empty, discovery endpoint is not empty but no operatorSelection in response
	clearSharedParam()
	discoveryResponse = &mcmodel.DiscoveryResponse{
		Links: []mcmodel.IDGatewayOperatorLink{},
	}
	globalConfig.DiscoveryEndpoint = fmt.Sprintf("%v/discovery_response", testingServerBaseURL)
	err = Authentication(nil, mcHandler, s)
	assert.Nil(t, err)
	assert.Equal(t, "no operatorSelection found in ApiExchange discovery response", s.ErrorMessage)
	assert.Equal(t, "no operatorSelection found in ApiExchange discovery response", sharedParams.Session.ErrorMessage)

	//s.UserInfo.Sub is empty, OK
	clearSharedParam()
	discoveryResponse = &mcmodel.DiscoveryResponse{
		Links: []mcmodel.IDGatewayOperatorLink{
			{
				Rel:  "operatorSelection",
				Href: discoveryURL,
			},
		},
	}
	err = Authentication(nil, mcHandler, s)
	assert.NotNil(t, sharedParams.Location)
	assert.Nil(t, err)
	assert.Equal(t, discoveryURL, *sharedParams.Location)
	assert.True(t, sharedParams.Redirect)

	//s.UserInfo.Sub is not empty, authorization endpoint is empty
	s.UserInfo = mcmodel.UserInfoResponse{
		Sub: "some subscriberId",
	}
	s.AuthorizeEndpoint = ""
	clearSharedParam()
	globalConfig.DiscoveryEndpoint = ""
	err = Authentication(nil, mcHandler, s)
	assert.Nil(t, err)
	assert.Equal(t, "Fail to initiate session with ApiExchange", s.ErrorMessage)
	assert.Equal(t, "Fail to initiate session with ApiExchange", sharedParams.Session.ErrorMessage)

	//s.UserInfo.Sub is not empty, OK with sub without +
	s.UserInfo = mcmodel.UserInfoResponse{
		Sub: "some subscriberId",
	}
	s.AuthorizeEndpoint = authorizeURL
	clearSharedParam()
	err = Authentication(nil, mcHandler, s)
	assert.Nil(t, err)
	assert.NotNil(t, sharedParams.Location)
	location, err := authorizeWithPCR(globalConfig, s, true)
	assert.Nil(t, err)
	assert.Equal(t, location, *sharedParams.Location)

	//s.UserInfo.Sub is not empty, OK with sub with +
	s.UserInfo = mcmodel.UserInfoResponse{
		Sub: "+123456789",
	}
	s.AuthorizeEndpoint = authorizeURL
	clearSharedParam()
	err = Authentication(nil, mcHandler, s)
	assert.Nil(t, err)
	assert.NotNil(t, sharedParams.Location)
	location, err = authorizeWithPCR(globalConfig, s, false)
	assert.Nil(t, err)
	assert.Equal(t, location, *sharedParams.Location)
}

func clearSharedParam() {
	sharedParams.Context = nil
	sharedParams.Session = nil
	sharedParams.Error = nil
	sharedParams.SetSession = nil
	sharedParams.Location = nil
	sharedParams.LoginSuccess = false
	sharedParams.CookieName = ""
	sharedParams.CookieValue = ""
	sharedParams.Redirect = false

}

type CustomMcApp struct {
}

func (app *CustomMcApp) GetHTTPClient() *http.Client {
	return httpClient
}
func (app *CustomMcApp) SetSession(session *session.Session) (id string, e error) {
	sharedParams.SetSession = session
	return "", nil
}
func (app *CustomMcApp) GetSessionFromStore(uuid *string) (s *session.Session, e error) {
	s = &session.Session{
		ID: "state",
		ErrorMessage: "",
	}
	return s, nil
}
func (app *CustomMcApp) DeleteSession(uuid *string) error {
	return nil
}
func (app *CustomMcApp) SetCookie(c interface{}, name string, value string) {
	sharedParams.CookieName = name
	sharedParams.CookieValue = value
}
func (app *CustomMcApp) GetCookie(c interface{}, name string) (string, error) {
	return "", nil
}
func (app *CustomMcApp) DeleteCookie(c interface{}, name string) {

}
func (app *CustomMcApp) SetSessionCookie(c interface{}, name string, value string) {
}
func (app *CustomMcApp) SetSessionContext(c interface{}, s *session.Session) {
}
func (app *CustomMcApp) GetConfig() *config.Config {
	return globalConfig
}
func (app *CustomMcApp) RedirectLogin(c interface{}, s *session.Session) error {
	sharedParams.Context = c
	sharedParams.Session = s
	return sharedParams.Error
}
func (app *CustomMcApp) RedirectLoginSuccess(c interface{}, s *session.Session) error {
	sharedParams.LoginSuccess = true
	return nil
}
func (app *CustomMcApp) RenderLogin(c interface{}, s *session.Session) error {
	return nil
}
func (app *CustomMcApp) RenderLandingPage(c interface{}, s *session.Session) error {
	return nil
}
func (app *CustomMcApp) Redirect(c interface{}, location *string) error {
	sharedParams.Context = c
	sharedParams.Location = location
	sharedParams.Redirect = true
	return sharedParams.Error
}
