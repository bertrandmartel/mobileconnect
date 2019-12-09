package jwt

import (
	"github.com/bertrandmartel/mobileconnect/sp/session"
	"github.com/bertrandmartel/mobileconnect/sp/application"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/lestrrat-go/jwx/jwk"
	"errors"
	"regexp"
	"time"
)

type JwtVerifyError  struct {
	ErrorType string
	Error error
}

const (
    JwtErrorSessionExpired = "SESSION_EXPIRED"
    JwtErrorUnauthorized   = "UNAUTHORIZED"
    JwtErrorValidation     = "JWT_VALIDATION_ERROR"
    JwtErrorTokenParse     = "JWT_TOKEN_PARSE_ERROR"
    JwtErrorNoJwksEndpoint = "JWT_JWKS_ENDPOINT_MISSING"
    JwtErrorOther          = "OTHER"
)

func checkJwtSkipFields(array *[]string, value string) bool{
	for _, element := range *array {
	    if element == value {
	    	return true
	    }
	}
	return false
}

func verifyJwt(idToken string, s *session.Session, app application.MobileConnectApp) JwtVerifyError {
	if s == nil {
		return JwtVerifyError{
			ErrorType: JwtErrorOther,
			Error: errors.New("session is nil"),
		}
	}
	if app == nil {
		return JwtVerifyError{
			ErrorType: JwtErrorOther,
			Error: errors.New("app is nil"),
		}
	}
	if s.JwksEndpoint == "" {
		return JwtVerifyError{
			ErrorType: JwtErrorNoJwksEndpoint,
			Error: errors.New("jwks endpoint is missing"),
		}
	}
	tokenRes, err := jwt.Parse(idToken, func (token *jwt.Token) (interface{}, error) {
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
	        return nil, errors.New("expecting JWT header to have string kid")
	    }

	    if key := s.JwkSet.LookupKeyID(keyID); len(key) == 1 {
	        return key[0].Materialize()
	    }
	    
	    return nil, fmt.Errorf("unable to find key %q", keyID)
	})
	if err != nil {
		if (err.Error() == "Token is expired"){
			return JwtVerifyError{
				ErrorType: JwtErrorSessionExpired,
				Error: err,
			}
		} else {
			return JwtVerifyError{
				ErrorType: JwtErrorTokenParse,
				Error: err,
			}
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
		return JwtVerifyError{
			ErrorType: JwtErrorValidation,
			Error: errors.New("iss field is missing"),
		}
	} else if !checkJwtSkipFields(&jwtVerificationSkip, "iss") {
		reg, err := regexp.Compile("/$")
		if err == nil {
			if (iss != reg.ReplaceAllString(s.Issuer, "")) {
				return JwtVerifyError{
					ErrorType: JwtErrorValidation,
					Error: errors.New(fmt.Sprintf("error validating issuer %v\n", iss)),
				}
			}
		} else {
			return JwtVerifyError{
				ErrorType: JwtErrorOther,
				Error: err,
			}
		}
	}
	if !subExist {
		return JwtVerifyError{
			ErrorType: JwtErrorValidation,
			Error: errors.New("sub field is missing"),
		}
	} else if !checkJwtSkipFields(&jwtVerificationSkip, "sub") {
		if (sub != s.UserInfo.Sub) {
			return JwtVerifyError{
				ErrorType: JwtErrorValidation,
				Error: errors.New(fmt.Sprintf("error validating sub %v\n", sub)),
			}
		}
	}
	if !expExist {
		return JwtVerifyError{
			ErrorType: JwtErrorValidation,
			Error: errors.New("exp field is missing"),
		}
	} else if !checkJwtSkipFields(&jwtVerificationSkip, "exp") {
		expiration, ok := exp.(float64)
		if !ok {
			return JwtVerifyError{
				ErrorType: JwtErrorValidation,
				Error: errors.New(fmt.Sprintf("error validating exp %v\n", exp)),
			}
		}
		if (int64(expiration) < (time.Now().Unix() - (60*60))) {
			return JwtVerifyError{
				ErrorType: JwtErrorSessionExpired,
				Error: errors.New(fmt.Sprintf("error validating exp : expected %v to be > than %v\n",int64(expiration), time.Now().Unix() - (60*60))),
			}
		} else {
			if (s.ExpirationTime != int64(expiration)){
		    	s.ExpirationTime = int64(expiration)
		    	app.SetSession(s)
			}
		}
	}
	if !nonceExist {
		return JwtVerifyError{
			ErrorType: JwtErrorValidation,
			Error: errors.New("nonce field is missing"),
		}
	} else if !checkJwtSkipFields(&jwtVerificationSkip, "nonce") {
		if (nonce != s.Nonce) {
			return JwtVerifyError{
				ErrorType: JwtErrorValidation,
				Error: errors.New(fmt.Sprintf("error validating nonce %v\n", nonce)),
			}
		}
	}
	if !acrExist {
		return JwtVerifyError{
			ErrorType: JwtErrorValidation,
			Error: errors.New("acr field is missing"),
		}
	} else if !checkJwtSkipFields(&jwtVerificationSkip, "acr") {
		if (acr != app.GetConfig().AuthOptions.AcrValues) {
			return JwtVerifyError{
				ErrorType: JwtErrorValidation,
				Error: errors.New(fmt.Sprintf("error validating acr %v\n", acr)),
			}
		}
	}
	return JwtVerifyError{
		Error: nil,
	}
}

func JwtMiddleware(context interface{}, s *session.Session, app application.MobileConnectApp) JwtVerifyError {
	cookie, err := app.GetCookie(context, session.JWTCookie)
	if err != nil {
		return JwtVerifyError{
			ErrorType: JwtErrorUnauthorized,
			Error: err,
		}
	}
	return verifyJwt(cookie, s, app)
}

func JwtMiddlewareWithErr(context interface{}, s *session.Session, app application.MobileConnectApp) error{
	jwtError := JwtMiddleware(context, s, app)
	if jwtError.Error != nil {
		if (jwtError.ErrorType == JwtErrorSessionExpired){
			s.ErrorMessage = "Your session has expired"
		} else if (jwtError.ErrorType == JwtErrorUnauthorized){
			s.ErrorMessage = "Your are not authorized to access this resource"
		} else {
			s.ErrorMessage = "authentication failed"
		}
		app.SetSession(s)
		return errors.New("jwt verification failed")
	}
	return nil
}