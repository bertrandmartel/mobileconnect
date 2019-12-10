package jwt

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/bertrandmartel/mobileconnect/sp/application"
	"github.com/bertrandmartel/mobileconnect/sp/config"
	"github.com/bertrandmartel/mobileconnect/sp/session"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
)

const testingServerBaseURL = "http://localhost:3233"

var idTokenExpired = "eyJraWQiOiIxZTlnZGs3IiwiYWxnIjoiUlMyNTYifQ.ewogImlzcyI6ICJodHRwOi8vc2VydmVyLmV4YW1wbGUuY29tIiwKICJzdWIiOiAiMjQ4Mjg5NzYxMDAxIiwKICJhdWQiOiAiczZCaGRSa3F0MyIsCiAibm9uY2UiOiAibi0wUzZfV3pBMk1qIiwKICJleHAiOiAxMzExMjgxOTcwLAogImlhdCI6IDEzMTEyODA5NzAsCiAibmFtZSI6ICJKYW5lIERvZSIsCiAiZ2l2ZW5fbmFtZSI6ICJKYW5lIiwKICJmYW1pbHlfbmFtZSI6ICJEb2UiLAogImdlbmRlciI6ICJmZW1hbGUiLAogImJpcnRoZGF0ZSI6ICIwMDAwLTEwLTMxIiwKICJlbWFpbCI6ICJqYW5lZG9lQGV4YW1wbGUuY29tIiwKICJwaWN0dXJlIjogImh0dHA6Ly9leGFtcGxlLmNvbS9qYW5lZG9lL21lLmpwZyIKfQ.rHQjEmBqn9Jre0OLykYNnspA10Qql2rvx4FsD00jwlB0Sym4NzpgvPKsDjn_wMkHxcp6CilPcoKrWHcipR2iAjzLvDNAReF97zoJqq880ZD1bwY82JDauCXELVR9O6_B0w3K-E7yM2macAAgNCUwtik6SjoSUZRcf-O5lygIyLENx882p6MtmwaL1hd6qn5RZOQ0TLrOYu0532g9Exxcm-ChymrB4xLykpDj3lUivJt63eEGGN6DH5K6o33TcxkIjNrCD4XB1CKKumZvCedgHHF3IAK4dVEDSUoGlH9z4pP_eWYNXvqQOjGs-rDaQzUHl6cQQWNiDpWOl_lxXjQEvQ"

var sharedParams = &SharedAppParams{}

var globalConfig = &config.Config{
	Version:           "0.1",
	Port:              6004,
	ServerPath:        "http://localhost",
	DiscoveryEndpoint: "https://discovery.sandbox.mobileconnect.io/v2/discovery",
	AuthOptions: config.AuthOptions{
		RedirectURI:         "http://localhost:6004/callback",
		Scope:               "openid mc_authz mc_identity_signup",
		Version:             "mc_di_r2_v2.3",
		AcrValues:           "2",
		ClientName:          "MCTesting",
		BindingMessage:      "some message",
		Context:             "Login",
		JwtVerificationSkip: []string{},
	},
	Client: config.Client{
		ClientID:     "client_id_for_discoverty",
		ClientSecret: "client_secret_for_discoverty",
		RedirectURI:  []string{"http://localhost:6004/discovery_callback"},
	},
}

var httpServer http.Server

var (
	verifyKey *rsa.PublicKey
	signKey   *rsa.PrivateKey
)

type Jwks struct {
	Keys []Key `json:"keys"`
}

type Key struct {
	E   string `json:"e"`
	N   string `json:"n"`
	Kty string `json:"kty"`
	Kid string `json:"kid"`
}

var jwksResponse = &Jwks{
	Keys: []Key{
		{
			E:   "AQAB",
			N:   "4SegXejZ28EiNU6eJh6nYuvHANqkbs-_AmjRgaNF5qF6igZKtY5tvLrKlCUbZmr-EQPadwUkO49iNfjMW7rhfi56gk0zRhHK0VWECuJjnp5uusOt4o9H4mRQNkAHmmx8rZ0qBlw9IXElj2w3dM9cDZnYYuHRl4FOqmGIBTHcqTBj0K8f1cH1jpLYfDSfMEu0WXbCPE4AfVZOHdUwSOfy290QLqQ_21rJ5GlyClG22SqQNt3ViRzfvTkE7BHMtSjzuOterNzVD14tzqP3xr2K5cjJKvfLlhP6YpJPdD0bvVosfkXR7qvpqM3s1dsjmETav4JI7n01hOTh1UWkjKAVslv9Odmf3n07j1Sx2Qyw0weU7a108Ojj8GbuxmConIbW3OzSdL7l4_rL9jo6e8Yo4ozIQZ5tUDOzITEVTCzG0fNOYYoTSqFIhVKw67LmICD_j3G9scBMYm-j0IKnk2pg3x4kU8sTkPuFjsz0sARpsm_dtB3IT4veCnx_kYD-HzBGerYHjGLKe50LpJttxV0B_2RGHOU2lEbberFZcFyJNCjvAcvIUu7JVvwKtUg5IyWS9suwdYN9D89SQ5HpKGGtv2EBS6Am36kRouLJBPGpZQoYlrY7ZWCAcm-zjDh6HcC2l0oUz7L_gLjzD0I0jHtzc4bwEYRnjz0HZrH2lsvkSMs",
			Kty: "RSA",
			Kid: "1e9gdk7",
		},
	},
}

var privKeyPath = "../../test/cert.key"
var pubKeyPath = "../../test/cert.pub"

func startHTTPServer() {
	httpServer := &http.Server{Addr: ":3233"}

	http.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(jwksResponse)
	})

	go func() {
		if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
			fmt.Println(fmt.Sprintf("ListenAndServe(): %s", err))
		}
	}()
}

func TestCheckJwtSkipFields(t *testing.T) {
	arr := []string{"1", "2"}
	res := checkJwtSkipFields(&arr, "1")
	assert.True(t, res)
	res = checkJwtSkipFields(&arr, "3")
	assert.False(t, res)
}

func TestVerifyJwt(t *testing.T) {
	//verifyJwt(idToken string, s *session.Session, app application.MobileConnectApp)
	var mcHandler application.MobileConnectApp = &CustomMcApp{}
	s := &session.Session{
		ErrorMessage: "",
	}
	//session is nil
	res := verifyJwt("", nil, mcHandler)
	assert.Equal(t, JwtErrorOther, res.ErrorType)
	assert.Equal(t, "session is nil", res.Error.Error())

	//app is nil
	res = verifyJwt("", s, nil)
	assert.Equal(t, JwtErrorOther, res.ErrorType)
	assert.Equal(t, "app is nil", res.Error.Error())

	//no jwks endpoint set
	res = verifyJwt("", s, mcHandler)
	assert.Equal(t, JwtErrorNoJwksEndpoint, res.ErrorType)
	assert.Equal(t, "jwks endpoint is missing", res.Error.Error())

	s.JwksEndpoint = fmt.Sprintf("%v/jwks", testingServerBaseURL)
	//id token format is incorrect
	res = verifyJwt("", s, mcHandler)
	assert.Equal(t, JwtErrorTokenParse, res.ErrorType)

	//jwk verification error
	res = verifyJwt(idTokenExpired, s, mcHandler)
	assert.Equal(t, JwtErrorTokenParse, res.ErrorType)
	assert.Equal(t, "crypto/rsa: verification error", res.Error.Error())

	token := jwt.New(jwt.GetSigningMethod("RS256"))
	token.Header["kid"] = "1e9gdk7"
	claims := make(jwt.MapClaims)
	token.Claims = claims
	tokenString, err := token.SignedString(signKey)
	assert.Nil(t, err)

	//no iss
	res = verifyJwt(tokenString, s, mcHandler)
	assert.Equal(t, JwtErrorValidation, res.ErrorType)
	assert.Equal(t, "iss field is missing", res.Error.Error())

	claims["iss"] = "some issuer"
	token.Claims = claims
	tokenString, _ = token.SignedString(signKey)

	//iss value is incorrect
	res = verifyJwt(tokenString, s, mcHandler)
	assert.Equal(t, JwtErrorValidation, res.ErrorType)
	assert.Equal(t, "error validating issuer some issuer\n", res.Error.Error())

	s.Issuer = "some issuer"

	//sub is missing
	res = verifyJwt(tokenString, s, mcHandler)
	assert.Equal(t, JwtErrorValidation, res.ErrorType)
	assert.Equal(t, "sub field is missing", res.Error.Error())

	claims["sub"] = "some sub value"
	token.Claims = claims
	tokenString, _ = token.SignedString(signKey)

	//sub value is incorrect
	res = verifyJwt(tokenString, s, mcHandler)
	assert.Equal(t, JwtErrorValidation, res.ErrorType)
	assert.Equal(t, "error validating sub some sub value\n", res.Error.Error())

	s.UserInfo.Sub = "some sub value"

	//exp is missing
	res = verifyJwt(tokenString, s, mcHandler)
	assert.Equal(t, JwtErrorValidation, res.ErrorType)
	assert.Equal(t, "exp field is missing", res.Error.Error())

	claims["exp"] = "some exp value"
	token.Claims = claims
	tokenString, _ = token.SignedString(signKey)

	//exp value is incorrect
	res = verifyJwt(tokenString, s, mcHandler)
	assert.Equal(t, JwtErrorValidation, res.ErrorType)
	assert.Equal(t, "error validating exp some exp value\n", res.Error.Error())

	claims["exp"] = time.Date(2000, 10, 10, 12, 0, 0, 0, time.UTC).Unix()
	token.Claims = claims
	tokenString, _ = token.SignedString(signKey)

	//exp value is correct but expired
	res = verifyJwt(tokenString, s, mcHandler)
	assert.Equal(t, JwtErrorSessionExpired, res.ErrorType)
	assert.Equal(t, res.Error.Error(), "Token is expired")

	claims["exp"] = time.Date(2100, 10, 10, 12, 0, 0, 0, time.UTC).Unix()
	token.Claims = claims
	tokenString, _ = token.SignedString(signKey)

	//nonce is missing
	res = verifyJwt(tokenString, s, mcHandler)
	assert.Equal(t, JwtErrorValidation, res.ErrorType)
	assert.Equal(t, "nonce field is missing", res.Error.Error())

	claims["nonce"] = "some nonce value"
	token.Claims = claims
	tokenString, _ = token.SignedString(signKey)

	//nonce value is incorrect
	res = verifyJwt(tokenString, s, mcHandler)
	assert.Equal(t, JwtErrorValidation, res.ErrorType)
	assert.Equal(t, "error validating nonce some nonce value\n", res.Error.Error())

	s.Nonce = "some nonce value"

	//acr is missing
	res = verifyJwt(tokenString, s, mcHandler)
	assert.Equal(t, JwtErrorValidation, res.ErrorType)
	assert.Equal(t, "acr field is missing", res.Error.Error())

	claims["acr"] = "3"
	token.Claims = claims
	tokenString, _ = token.SignedString(signKey)

	//acr value is incorrect
	res = verifyJwt(tokenString, s, mcHandler)
	assert.Equal(t, JwtErrorValidation, res.ErrorType)
	assert.Equal(t, "error validating acr 3\n", res.Error.Error())

	globalConfig.AuthOptions.AcrValues = "3"

	//ok
	res = verifyJwt(tokenString, s, mcHandler)
	assert.Nil(t, res.Error)

	//skip nonce validation
	s.Nonce = "some other nonce"
	globalConfig.AuthOptions.JwtVerificationSkip = append(globalConfig.AuthOptions.JwtVerificationSkip, "nonce")
	res = verifyJwt(tokenString, s, mcHandler)
	assert.Nil(t, res.Error)
}

func TestJwtMiddleware(t *testing.T) {

}

func TestJwtMiddlewareWithErr(t *testing.T) {

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
	signBytes, err := ioutil.ReadFile(privKeyPath)
	if err != nil {
		fmt.Println(err)
	}
	signKey, err = jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	if err != nil {
		fmt.Println(err)
	}
	verifyBytes, err := ioutil.ReadFile(pubKeyPath)
	if err != nil {
		fmt.Println(err)
	}
	verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
	if err != nil {
		fmt.Println(err)
	}
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

type CustomMcApp struct {
}

func (app *CustomMcApp) GetHTTPClient() *http.Client {
	return nil
}
func (app *CustomMcApp) SetSession(session *session.Session) (id string, e error) {
	sharedParams.SetSession = session
	return "", nil
}
func (app *CustomMcApp) GetSessionFromStore(uuid *string) (s *session.Session, e error) {
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
