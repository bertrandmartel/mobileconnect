package jwt

import (
	"fmt"
	"regexp"
	"time"

	"github.com/bertrandmartel/mobileconnect/sp/application"
	"github.com/bertrandmartel/mobileconnect/sp/session"
	"github.com/dgrijalva/jwt-go"
	"github.com/lestrrat-go/jwx/jwk"
)

type VerifyError struct {
	ErrorType string
	Error     error
}

const (
	JwtErrorSessionExpired = "SESSION_EXPIRED"
	JwtErrorUnauthorized   = "UNAUTHORIZED"
	JwtErrorValidation     = "JWT_VALIDATION_ERROR"
	JwtErrorTokenParse     = "JWT_TOKEN_PARSE_ERROR"
	JwtErrorNoJwksEndpoint = "JWT_JWKS_ENDPOINT_MISSING"
	JwtErrorOther          = "OTHER"
)

func checkJwtSkipFields(array *[]string, value string) bool {
	for _, element := range *array {
		if element == value {
			return true
		}
	}
	return false
}

func verifyJwt(idToken string, s *session.Session, app application.MobileConnectApp) VerifyError {
	if s == nil {
		return VerifyError{
			ErrorType: JwtErrorOther,
			Error:     fmt.Errorf("session is nil"),
		}
	}
	if app == nil {
		return VerifyError{
			ErrorType: JwtErrorOther,
			Error:     fmt.Errorf("app is nil"),
		}
	}
	if s.JwksEndpoint == "" {
		return VerifyError{
			ErrorType: JwtErrorNoJwksEndpoint,
			Error:     fmt.Errorf("jwks endpoint is missing"),
		}
	}
	tokenRes, err := jwt.Parse(idToken, func(token *jwt.Token) (interface{}, error) {
		if len(s.JwkSet.Keys) == 0 {
			set, err := jwk.FetchHTTP(s.JwksEndpoint)
			if err != nil {
				return nil, err
			}
			s.JwkSet = *set
			app.SetSession(s)
		}
		keyID, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("expecting JWT header to have string kid")
		}

		if key := s.JwkSet.LookupKeyID(keyID); len(key) == 1 {
			return key[0].Materialize()
		}

		return nil, fmt.Errorf("unable to find key %q", keyID)
	})
	if err != nil {
		if err.Error() == "Token is expired" {
			return VerifyError{
				ErrorType: JwtErrorSessionExpired,
				Error:     err,
			}
		}
		return VerifyError{
			ErrorType: JwtErrorTokenParse,
			Error:     err,
		}
	}
	claims := tokenRes.Claims.(jwt.MapClaims)
	jwtVerificationSkip := app.GetConfig().AuthOptions.JwtVerificationSkip
	iss, issExist := claims["iss"]
	sub, subExist := claims["sub"]
	exp, expExist := claims["exp"]
	nonce, nonceExist := claims["nonce"]
	acr, acrExist := claims["acr"]
	if !issExist {
		return VerifyError{
			ErrorType: JwtErrorValidation,
			Error:     fmt.Errorf("iss field is missing"),
		}
	} else if !checkJwtSkipFields(&jwtVerificationSkip, "iss") {
		reg := regexp.MustCompile("/$")
		if iss != reg.ReplaceAllString(s.Issuer, "") {
			return VerifyError{
				ErrorType: JwtErrorValidation,
				Error:     fmt.Errorf(fmt.Sprintf("error validating issuer %v\n", iss)),
			}
		}
	}
	if !subExist {
		return VerifyError{
			ErrorType: JwtErrorValidation,
			Error:     fmt.Errorf("sub field is missing"),
		}
	} else if !checkJwtSkipFields(&jwtVerificationSkip, "sub") {
		if sub != s.UserInfo.Sub {
			return VerifyError{
				ErrorType: JwtErrorValidation,
				Error:     fmt.Errorf(fmt.Sprintf("error validating sub %v\n", sub)),
			}
		}
	}
	if !expExist {
		return VerifyError{
			ErrorType: JwtErrorValidation,
			Error:     fmt.Errorf("exp field is missing"),
		}
	} else if !checkJwtSkipFields(&jwtVerificationSkip, "exp") {
		expiration, ok := exp.(float64)
		if !ok {
			return VerifyError{
				ErrorType: JwtErrorValidation,
				Error:     fmt.Errorf(fmt.Sprintf("error validating exp %v\n", exp)),
			}
		}
		if int64(expiration) < (time.Now().Unix() - (60 * 60)) {
			return VerifyError{
				ErrorType: JwtErrorSessionExpired,
				Error:     fmt.Errorf(fmt.Sprintf("error validating exp : expected %v to be > than %v\n", int64(expiration), time.Now().Unix()-(60*60))),
			}
		} else if s.ExpirationTime != int64(expiration) {
			s.ExpirationTime = int64(expiration)
			app.SetSession(s)
		}
	}
	if !nonceExist {
		return VerifyError{
			ErrorType: JwtErrorValidation,
			Error:     fmt.Errorf("nonce field is missing"),
		}
	} else if !checkJwtSkipFields(&jwtVerificationSkip, "nonce") {
		if nonce != s.Nonce {
			return VerifyError{
				ErrorType: JwtErrorValidation,
				Error:     fmt.Errorf(fmt.Sprintf("error validating nonce %v\n", nonce)),
			}
		}
	}
	if !acrExist {
		return VerifyError{
			ErrorType: JwtErrorValidation,
			Error:     fmt.Errorf("acr field is missing"),
		}
	} else if !checkJwtSkipFields(&jwtVerificationSkip, "acr") {
		if acr != app.GetConfig().AuthOptions.AcrValues {
			return VerifyError{
				ErrorType: JwtErrorValidation,
				Error:     fmt.Errorf(fmt.Sprintf("error validating acr %v\n", acr)),
			}
		}
	}
	return VerifyError{
		Error: nil,
	}
}

func Middleware(context interface{}, s *session.Session, app application.MobileConnectApp) VerifyError {
	cookie, err := app.GetCookie(context, session.JWTCookie)
	if err != nil {
		return VerifyError{
			ErrorType: JwtErrorUnauthorized,
			Error:     err,
		}
	}
	return verifyJwt(cookie, s, app)
}

func MiddlewareWithErr(context interface{}, s *session.Session, app application.MobileConnectApp) error {
	jwtError := Middleware(context, s, app)
	if jwtError.Error != nil {
		switch jwtError.ErrorType {
		case JwtErrorSessionExpired:
			s.ErrorMessage = "Your session has expired"
		case JwtErrorUnauthorized:
			s.ErrorMessage = "Your are not authorized to access this resource"
		default:
			s.ErrorMessage = "authentication failed"
		}
		app.SetSession(s)
		return fmt.Errorf("jwt verification failed")
	}
	return nil
}
