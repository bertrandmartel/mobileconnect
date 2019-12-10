package middleware

import (
	"github.com/bertrandmartel/mobileconnect/sp/application"
	"github.com/bertrandmartel/mobileconnect/sp/session"
	uuid "github.com/satori/go.uuid"
)

func UseSession(context interface{}, app application.MobileConnectApp) {
	cookie, err := app.GetCookie(context, session.SessionCookie)
	if err != nil {
		s := &session.Session{
			ID: uuid.NewV4().String(),
		}
		sessionVal, err := app.SetSession(s)
		if err != nil {
			return
		}
		app.SetSessionCookie(context, session.SessionCookie, sessionVal)
		app.SetSessionContext(context, s)
	} else {
		s, err := app.GetSessionFromStore(&cookie)
		if err != nil {
			return
		}
		app.SetSessionContext(context, s)
	}
}

func UseClearSession(context interface{}, app application.MobileConnectApp) {
	cookie, err := app.GetCookie(context, session.SessionCookie)
	if err == nil {
		app.DeleteSession(&cookie)
	}
	app.DeleteCookie(context, session.SessionCookie)
	app.DeleteCookie(context, session.JWTCookie)
}
