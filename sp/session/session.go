package session

import (
	"github.com/bertrandmartel/mobileconnect/sp/mcmodel"
	"github.com/lestrrat-go/jwx/jwk"
)

const SessionCookie = "MC"
const JWTCookie = "JWT"

type Session struct {
	ID                string                   `json:"id"`
	ErrorMessage      string                   `json:"error_message"`
	UserInfo          mcmodel.UserInfoResponse `json:"user_info"`
	Nonce             string                   `json:"nonce"`
	JwksEndpoint      string                   `json:"jwks_endpoint"`
	AuthorizeEndpoint string                   `json:"authorize_endpoint"`
	Issuer            string                   `json:"issuer"`
	OperatorConfig    mcmodel.OperatorConfig   `json:"operator_config"`
	JwkSet            jwk.Set                  `json:"jwks"`
	ExpirationTime    int64                    `json:"expiration_time"`
	Metadata          string                   `json:"metadata"`
	CookieTimeout     int64                    `json:"cookie_timeout"`
}
