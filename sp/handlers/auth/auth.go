package auth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/bertrandmartel/mobileconnect/sp/application"
	"github.com/bertrandmartel/mobileconnect/sp/config"
	"github.com/bertrandmartel/mobileconnect/sp/mcmodel"
	"github.com/bertrandmartel/mobileconnect/sp/session"
	uuid "github.com/satori/go.uuid"
	//"io/ioutil"
)

func fetchDiscovery(httpClient *http.Client, url string, target interface{}, authorization string, redirectURI string) error {
	if httpClient == nil {
		return errors.New("no http client specified")
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", fmt.Sprintf("Basic %v", authorization))

	q := req.URL.Query()
	q.Add("Redirect_URL", redirectURI)
	req.URL.RawQuery = q.Encode()

	r, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	if r.StatusCode == 404 {
		return errors.New("record was not found")
	}
	if r.StatusCode != 202 {
		return errors.New("received incorrect status : " + strconv.Itoa(r.StatusCode))
	}
	return json.NewDecoder(r.Body).Decode(target)
}

func fetchOperator(httpClient *http.Client, config *config.Config, target interface{}, mccMnc []string) error {
	if httpClient == nil {
		return errors.New("no http client specified")
	}
	if config == nil {
		return errors.New("no config specified")
	}
	if len(mccMnc) != 2 {
		return errors.New("wrong mcc mnc value")
	}
	authorization := fmt.Sprintf("%v:%v", config.Client.ClientID, config.Client.ClientSecret)

	req, err := http.NewRequest("GET", config.DiscoveryEndpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Add("Accept", "*/*")
	req.Header.Add("Authorization", fmt.Sprintf("Basic %v", base64.StdEncoding.EncodeToString([]byte(authorization))))

	q := req.URL.Query()
	q.Add("Redirect_URL", config.Client.RedirectURI[0])
	q.Add("Selected-MCC", mccMnc[0])
	q.Add("Selected-MNC", mccMnc[1])
	req.URL.RawQuery = q.Encode()

	r, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	if r.StatusCode == 404 {
		return errors.New("record was not found")
	}
	if r.StatusCode != 200 {
		return errors.New("received incorrect status : " + strconv.Itoa(r.StatusCode))
	}
	return json.NewDecoder(r.Body).Decode(target)
}

func fetchToken(httpClient *http.Client, endpointURL string, target interface{}, authorization string, code string, redirectURI string) error {
	if httpClient == nil {
		return errors.New("no http client specified")
	}
	form := url.Values{}
	form.Add("grant_type", "authorization_code")
	form.Add("code", code)
	form.Add("redirect_uri", redirectURI)
	req, err := http.NewRequest("POST", endpointURL, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Add("Accept", "*/*")
	req.Header.Add("Authorization", fmt.Sprintf("Basic %v", authorization))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	r, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	/*
		fmt.Println(r.StatusCode)
		bodyBytes, err := ioutil.ReadAll(r.Body)
		if err != nil {
			return err
		}
		bodyString := string(bodyBytes)
		fmt.Println(bodyString)
	*/
	if r.StatusCode == 404 {
		return errors.New("record was not found")
	}
	if r.StatusCode != 200 {
		return errors.New("received incorrect status : " + strconv.Itoa(r.StatusCode))
	}
	return json.NewDecoder(r.Body).Decode(target)
}

func fetchUserInfo(httpClient *http.Client, endpointURL string, target interface{}, token string) error {
	if httpClient == nil {
		return errors.New("no http client specified")
	}
	req, err := http.NewRequest("GET", endpointURL, nil)
	if err != nil {
		return err
	}
	req.Header.Add("Accept", "*/*")
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %v", token))

	r, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer r.Body.Close()

	if r.StatusCode == 404 {
		return errors.New("record was not found")
	}
	if r.StatusCode != 200 {
		return errors.New("received incorrect status : " + strconv.Itoa(r.StatusCode))
	}
	return json.NewDecoder(r.Body).Decode(target)
}

func authorize(operatorConfig *mcmodel.OperatorConfig,
	config *config.Config,
	state string,
	subscriberID string,
	nonce string) (string, error) {
	if operatorConfig == nil {
		return "", errors.New("operatorConfig is nil")
	}
	if config == nil {
		return "", errors.New("config is nil")
	}

	authorizationURL := searchLinkField(&operatorConfig.Apis.OperatorID.Link, "authorization")
	if authorizationURL == "" {
		return "", errors.New("authorization url not found")
	}
	u, err := url.Parse(authorizationURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Add("client_id", operatorConfig.ClientID)
	q.Add("redirect_uri", config.AuthOptions.RedirectURI)
	q.Add("response_type", "code")
	q.Add("scope", config.AuthOptions.Scope)
	q.Add("version", config.AuthOptions.Version)
	q.Add("state", state)
	q.Add("nonce", nonce)
	q.Add("login_hint", fmt.Sprintf("ENCR_MSISDN:%v", subscriberID))
	q.Add("acr_values", config.AuthOptions.AcrValues)
	q.Add("client_name", config.AuthOptions.ClientName)
	q.Add("binding_message", config.AuthOptions.BindingMessage)
	q.Add("context", config.AuthOptions.Context)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func authorizeWithPCR(config *config.Config,
	s *session.Session,
	pcr bool) (string, error) {
	if config == nil {
		return "", errors.New("config is nil")
	}
	if s == nil {
		return "", errors.New("session is nil")
	}
	if s.AuthorizeEndpoint == "" {
		return "", errors.New("authorization url not found")
	}
	u, err := url.Parse(s.AuthorizeEndpoint)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Add("client_id", s.OperatorConfig.ClientID)
	q.Add("redirect_uri", config.AuthOptions.RedirectURI)
	q.Add("response_type", "code")
	q.Add("scope", config.AuthOptions.Scope)
	q.Add("version", config.AuthOptions.Version)
	q.Add("state", s.ID)
	q.Add("nonce", s.Nonce)
	if pcr {
		q.Add("login_hint", fmt.Sprintf("PCR:%v", s.UserInfo.Sub))
	} else {
		q.Add("login_hint", fmt.Sprintf("%v", s.UserInfo.Sub))
	}
	q.Add("acr_values", config.AuthOptions.AcrValues)
	q.Add("client_name", config.AuthOptions.ClientName)
	q.Add("binding_message", config.AuthOptions.BindingMessage)
	q.Add("context", config.AuthOptions.Context)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func renderFailedLogin(context interface{}, message string, app *application.MobileConnectApp, s *session.Session) error {
	if app == nil {
		return errors.New("app is nil")
	}
	if s == nil {
		return errors.New("session is nil")
	}
	if message != "" {
		s.ErrorMessage = message
		(*app).SetSession(s)
	}
	return (*app).RedirectLogin(context, s)
}

func searchLinkField(links *[]mcmodel.IDGatewayOperatorLink, field string) string {
	if links == nil {
		return ""
	}
	linkArr := *links
	for i := range linkArr {
		if linkArr[i].Rel == field {
			return linkArr[i].Href
		}
	}
	return ""
}

func Process(context interface{},
	request *mcmodel.DiscoveryRequest,
	app application.MobileConnectApp,
	s *session.Session) error {
	if request == nil {
		return renderFailedLogin(context, "request is nil", &app, s)
	}
	if s == nil {
		return renderFailedLogin(context, "session is nil", &app, s)
	}
	if request.ErrorMessage != "" {
		switch request.ErrorMessage {
		case "MSISDNNotFound":
			return renderFailedLogin(context, "Mobile Connect is not supported for this phone number", &app, s)
		case "NotSupportedOperatorMSISDN":
			return renderFailedLogin(context, "Operator for this phone number was not found", &app, s)
		default:
			return renderFailedLogin(context, request.ErrorMessage, &app, s)
		}
	}
	if request.SubscriberID == "" || request.MccMnc == "" {
		return renderFailedLogin(context, "ApiExchange failed to send required parameters", &app, s)
	}
	mccSplit := strings.Split(request.MccMnc, "_")
	if len(mccSplit) != 2 {
		return renderFailedLogin(context, "Bad MCC/MNC format", &app, s)
	}
	//request all endpoints for MNO defined by mcc_mnc (https://developer.mobileconnect.io/discovery-api#tag/DISCOVERY%2Fpaths%2F~1discovery%2Fget)
	mccMncDiscoveryResponse := new(mcmodel.MccMncDiscoveryResponse)
	err := fetchOperator(
		app.GetHTTPClient(),
		app.GetConfig(),
		mccMncDiscoveryResponse,
		mccSplit,
	)
	if err != nil {
		log.Println(err)
		return renderFailedLogin(context, "Fail to find operator", &app, s)
	}
	s.Nonce = uuid.NewV4().String()
	s.OperatorConfig = mccMncDiscoveryResponse.Response
	app.SetSession(s)
	location, err := authorize(&mccMncDiscoveryResponse.Response, app.GetConfig(), s.ID, request.SubscriberID, s.Nonce)
	if err != nil {
		fmt.Println(err)
		return renderFailedLogin(context, err.Error(), &app, s)
	}
	return app.Redirect(context, &location)
}

func Callback(context interface{}, request *mcmodel.LoginCallback, app application.MobileConnectApp) error {
	if request == nil {
		return renderFailedLogin(context, "request is nil", &app, nil)
	}
	//get the session from the state value in case cookie was not forwarded to /authorize
	s, err := app.GetSessionFromStore(&request.State)
	if err != nil {
		fmt.Println(err)
		return renderFailedLogin(context, "session is nil", &app, s)
	}
	if s == nil {
		return renderFailedLogin(context, "session is nil", &app, s)
	}
	if request.Error != "" {
		fmt.Println(request)
		return renderFailedLogin(context, fmt.Sprintf("%v : %v", request.Error, request.ErrorDescription), &app, s)
	}
	if request.Code != "" /*&& request.State != ""*/ {
		tokenEndpoint := searchLinkField(&s.OperatorConfig.Apis.OperatorID.Link, "token")
		if tokenEndpoint == "" {
			return renderFailedLogin(context, "token endpoint not found in operator config", &app, s)
		}
		userInfoEndpoint := searchLinkField(&s.OperatorConfig.Apis.OperatorID.Link, "premiuminfo")
		if userInfoEndpoint == "" {
			return renderFailedLogin(context, "premiuminfo endpoint not found in operator config", &app, s)
		}
		authorization := fmt.Sprintf("%v:%v", s.OperatorConfig.ClientID, s.OperatorConfig.ClientSecret)
		tokenResponse := new(mcmodel.TokenResponse)

		err := fetchToken(app.GetHTTPClient(), tokenEndpoint, tokenResponse, base64.StdEncoding.EncodeToString([]byte(authorization)), request.Code, app.GetConfig().AuthOptions.RedirectURI)
		if err != nil {
			return renderFailedLogin(context, "Fail to get token", &app, s)
		}
		userInfoResponse := new(mcmodel.UserInfoResponse)
		err = fetchUserInfo(app.GetHTTPClient(), userInfoEndpoint, userInfoResponse, tokenResponse.AccessToken)
		if err != nil {
			return renderFailedLogin(context, "Fail to get userinfo", &app, s)
		}
		fmt.Println("user info")
		fmt.Println(userInfoResponse.Sub)
		//Here record in operatorConfig & userInfoResponse in session
		s.JwksEndpoint = searchLinkField(&s.OperatorConfig.Apis.OperatorID.Link, "jwks")
		if s.JwksEndpoint == "" {
			return renderFailedLogin(context, "jwks endpoint not found in operator config", &app, s)
		}
		s.AuthorizeEndpoint = searchLinkField(&s.OperatorConfig.Apis.OperatorID.Link, "authorization")
		if s.AuthorizeEndpoint == "" {
			return renderFailedLogin(context, "authorization endpoint not found in operator config", &app, s)
		}
		s.Issuer = searchLinkField(&s.OperatorConfig.Apis.OperatorID.Link, "issuer")
		if s.Issuer == "" {
			return renderFailedLogin(context, "issuer value not found in operator config", &app, s)
		}
		s.UserInfo = *userInfoResponse
		app.SetSession(s)
		app.SetCookie(context, session.JWTCookie, tokenResponse.IDToken)

		//we need to set the session cookie in case cookie were not forwared in /authorize request
		sessionVal, err := app.SetSession(s)
		if err != nil {
			return renderFailedLogin(context, "failed to set session", &app, s)
		}
		app.SetSessionCookie(context, session.SessionCookie, sessionVal)
		app.SetSessionContext(context, s)

		return app.RedirectLoginSuccess(context, s)
	}
	return app.RedirectLogin(context, s)
}

func Authentication(context interface{}, app application.MobileConnectApp, s *session.Session) error {
	if s == nil {
		return renderFailedLogin(context, "session is nil", &app, s)
	}
	if s.UserInfo.Sub != "" {
		s.Nonce = uuid.NewV4().String()
		app.SetSession(s)
		pcr := true
		if strings.HasPrefix(s.UserInfo.Sub, "+") {
			pcr = false
		}
		location, err := authorizeWithPCR(app.GetConfig(), s, pcr)
		if err != nil {
			return renderFailedLogin(context, "Fail to initiate session with ApiExchange", &app, s)
		}
		return app.Redirect(context, &location)
	}
	authorization := fmt.Sprintf("%v:%v", app.GetConfig().Client.ClientID, app.GetConfig().Client.ClientSecret)
	discoveryResponse := new(mcmodel.DiscoveryResponse)
	err := fetchDiscovery(
		app.GetHTTPClient(),
		app.GetConfig().DiscoveryEndpoint,
		discoveryResponse,
		base64.StdEncoding.EncodeToString([]byte(authorization)),
		app.GetConfig().Client.RedirectURI[0])
	if err != nil {
		fmt.Println(err)
		return renderFailedLogin(context, "Fail to initiate session with ApiExchange", &app, s)
	}
	location := searchLinkField(&discoveryResponse.Links, "operatorSelection")
	if location == "" {
		return renderFailedLogin(context, "no operatorSelection found in ApiExchange discovery response", &app, s)
	}
	fmt.Println(app.GetConfig().DiscoveryEndpoint)
	return app.Redirect(context, &location)
}
