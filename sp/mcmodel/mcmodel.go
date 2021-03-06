package mcmodel

//https://developer.mobileconnect.io/discovery-api#tag/DISCOVERY%2Fpaths%2F~1discovery~1operator-selection%2Fget
type DiscoveryRequest struct {
	SubscriberID string `query:"subscriber_id"`
	MccMnc       string `query:"mcc_mnc"`
	ErrorMessage string `query:"err_msg"`
}

//https://developer.mobileconnect.io/discovery-api#tag/DISCOVERY%2Fpaths%2F~1discovery%3F%5BRedirect_URL%5D~1%2Fget
type DiscoveryResponse struct {
	Links []IDGatewayOperatorLink `json:"links"`
}

//GET http://localhost:6005/disocvery?RedirectURL=http://localhost:6004/discovery_callback
type DiscoverySessionRequest struct {
	RedirectURL   string `query:"Redirect_URL" validate:"required"` //The redirect URL of your application or service. Used as an additional validation parameter. The redirect URL is defined when you register your application on the Developer Portal
	IgnoreCookies string `query:"Ignore-Cookies"`                   //Disables cookies. Intended to make testing easier in situations where the results are likely to change. Usage is mandatory only when it is true.
	CorrelationID string `query:"correlation_id"`                   //Correlates a transaction across Mobile Connect components. The value is generated by the Service Provider and must be locally unique.
	MCC           string `query:"Selected-MCC"`
	MNC           string `query:"Selected-MNC"`
}

type OperatorSelectionRequest struct {
	SessionID string `query:"session_id" validate:"required"` //Session ID
}

type RedirectLink struct {
	Href string `json:"href"`
	Rel  string `json:"operatorSelection"`
}

type DiscoverySessionResponse struct {
	Link RedirectLink `json:"link"`
}

type Session struct {
	ClientID    string `json:"client_id"`
	RedirectURI string `json:"redirect_uri"`
}

type SelectOperatorRequest struct {
	SessionID string `form:"session_id" validate:"required"`
	MSISDN    string `form:"msisdn" validate:"required"`
}

type M map[string]string

type JwkResponse struct {
	Keys []M `json:"keys"`
}

type MccMncDiscoveryResponse struct {
	TTL      int            `json:"ttl"`
	Response OperatorConfig `json:"response"`
}

type OperatorConfig struct {
	ClientID        string       `json:"client_id"`
	ClientSecret    string       `json:"client_secret"`
	ServingOperator string       `json:"serving_operator"`
	Country         string       `json:"country"`
	Currency        string       `json:"currency"`
	Apis            IDGatewayAPI `json:"apis"`
}

type IDGatewayAPI struct {
	OperatorID IDGatewayOperatorMeta `json:"operatorid"`
}

type IDGatewayOperatorMeta struct {
	Link []IDGatewayOperatorLink `json:"link"`
}

type IDGatewayOperatorLink struct {
	Rel  string `json:"rel"`
	Href string `json:"href"`
}

type LoginCallback struct {
	Error            string `query:"error"`
	ErrorDescription string `query:"error_description"`
	Code             string `query:"code"`
	State            string `query:"state"`
}

type TokenResponse struct {
	AccessToken   string      `json:"access_token"`
	TokenType     string      `json:"token_type"`
	ExpiresIn     interface{} `json:"expires_in"`
	IDToken       string      `json:"id_token"`
	CorrelationID string      `json:"correlation_id"`
}

type UserInfoResponse struct {
	Sub                  string `json:"sub"`
	PhoneNumberAlternate string `json:"phone_number_alternate"`
	Title                string `json:"title"`
	GivenName            string `json:"given_name"`
	FamilyName           string `json:"family_name"`
	MiddleName           string `json:"middle_name"`
	StreetAddress        string `json:"street_address"`
	City                 string `json:"city"`
	State                string `json:"state"`
	PostalCode           string `json:"postal_code"`
	Country              string `json:"country"`
	Email                string `json:"email"`
}
