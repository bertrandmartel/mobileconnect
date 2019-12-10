package application

import (
	"net/http"

	"github.com/bertrandmartel/mobileconnect/sp/config"
	"github.com/bertrandmartel/mobileconnect/sp/session"
)

type MobileConnectApp interface {
	GetHTTPClient() *http.Client
	SetSession(*session.Session) (id string, e error)
	GetSessionFromStore(uuid *string) (s *session.Session, e error)
	DeleteSession(uuid *string) error
	GetConfig() *config.Config
	SetCookie(c interface{}, name string, value string)
	GetCookie(c interface{}, name string) (string, error)
	DeleteCookie(c interface{}, name string)
	SetSessionCookie(c interface{}, name string, value string)
	SetSessionContext(c interface{}, s *session.Session)
	RedirectLogin(c interface{}, s *session.Session) error
	RedirectLoginSuccess(c interface{}, s *session.Session) error
	RenderLogin(c interface{}, s *session.Session) error
	RenderLandingPage(c interface{}, s *session.Session) error
	Redirect(c interface{}, location *string) error
}
