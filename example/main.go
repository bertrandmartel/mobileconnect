package main

import (
	"encoding/json"
	"html/template"
	"io"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/bertrandmartel/mobileconnect/sp/application"
	"github.com/bertrandmartel/mobileconnect/sp/config"
	"github.com/bertrandmartel/mobileconnect/sp/handlers/auth"
	"github.com/bertrandmartel/mobileconnect/sp/jwt"
	"github.com/bertrandmartel/mobileconnect/sp/mcmodel"
	"github.com/bertrandmartel/mobileconnect/sp/middleware"
	"github.com/bertrandmartel/mobileconnect/sp/session"
	"github.com/go-redis/redis/v7"
	"github.com/labstack/echo/v4"
	mw "github.com/labstack/echo/v4/middleware"
	"github.com/lestrrat-go/jwx/jwk"
	"gopkg.in/go-playground/validator.v9"
)

type Template struct {
	templates *template.Template
}

func (t *Template) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return t.templates.ExecuteTemplate(w, name, data)
}

func main() {
	config, err := config.ParseConfig("config-sandbox.json")
	if err != nil {
		log.Fatal(err)
		return
	}
	log.Printf("[SP] version %v\n", config.Version)
	log.Printf("[SP] server path %v:%v\n", config.ServerPath, config.Port)
	redisClient := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "",
		DB:       1,
	})
	t := &Template{
		templates: template.Must(template.ParseGlob("example/views/templates/*.html")),
	}
	e := echo.New()
	e.Renderer = t
	UseCommonMiddleware(e)
	var httpClient = &http.Client{
		Timeout: 10 * time.Second,
	}
	routes(e, config, redisClient, httpClient)
	e.Logger.Fatal(e.Start(":" + strconv.Itoa(config.Port)))
}

func routes(e *echo.Echo, config *config.Config, conn *redis.Client, httpClient *http.Client) {
	//init the render interface
	var mcHandler application.MobileConnectApp = &CustomMcApp{
		Config:      config,
		RedisClient: conn,
		HTTPClient:  httpClient,
	}
	e.Use(bindApp(&mcHandler))

	e.POST("/login", func(c echo.Context) error {
		app := *c.Get("application").(*application.MobileConnectApp)
		s := c.Get("session").(*session.Session)
		return auth.Authentication(c, app, s)
	}, MWSession)
	e.GET("/discovery_callback", func(c echo.Context) error {
		app := *c.Get("application").(*application.MobileConnectApp)
		s := c.Get("session").(*session.Session)
		request := new(mcmodel.DiscoveryRequest)
		if err := c.Bind(request); err != nil {
			return c.JSON(http.StatusBadRequest, SendError("invalid_request", "incorrect parameters"))
		}
		return auth.Process(c, request, app, s)
	}, MWSession)
	e.GET("/callback", func(c echo.Context) error {
		app := *c.Get("application").(*application.MobileConnectApp)
		request := new(mcmodel.LoginCallback)
		if err := c.Bind(request); err != nil {
			return c.JSON(http.StatusBadRequest, SendError("invalid_request", "incorrect parameters"))
		}
		return auth.Callback(c, request, app)
	}, MWSession)

	e.GET("/logout", func(c echo.Context) error {
		app := c.Get("application").(*application.MobileConnectApp)
		return (*app).RedirectLogin(c, nil)
	}, MWClearSession)

	e.GET("/login", func(c echo.Context) error {
		app := c.Get("application").(*application.MobileConnectApp)
		s := c.Get("session").(*session.Session)
		return (*app).RenderLogin(c, s)
	}, MWSession, MWJwtRedirectApp)

	//landing page
	e.GET("/app", func(c echo.Context) error {
		s := c.Get("session").(*session.Session)
		app := c.Get("application").(*application.MobileConnectApp)
		return (*app).RenderLandingPage(c, s)
	}, MWSession, MWJwt)

	e.Static("/static", "example/views/assets")
}

func bindApp(app *application.MobileConnectApp) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			c.Set("application", app)
			return next(c)
		}
	}
}

type CustomMcApp struct {
	Config      *config.Config
	RedisClient *redis.Client
	HTTPClient  *http.Client
}

func (app *CustomMcApp) GetHTTPClient() *http.Client {
	return app.HTTPClient
}
func (app *CustomMcApp) SetSession(session *session.Session) (id string, e error) {
	sessionKey := session.ID
	if session.JwkSet.Keys == nil {
		session.JwkSet.Keys = []jwk.Key{}
	}
	sessionJSON, err := json.Marshal(*session)
	if err != nil {
		return "", err
	}
	err = app.RedisClient.Set("session:"+sessionKey, sessionJSON, time.Hour).Err()
	if err != nil {
		return "", err
	}
	return sessionKey, nil
}
func (app *CustomMcApp) GetSessionFromStore(uuid *string) (s *session.Session, e error) {
	r, err := app.RedisClient.Get("session:" + *uuid).Result()
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal([]byte(r), &s)
	if err != nil {
		return nil, err
	}
	return s, nil
}
func (app *CustomMcApp) DeleteSession(uuid *string) error {
	return app.RedisClient.Del(*uuid).Err()
}
func (app *CustomMcApp) SetCookie(c interface{}, name string, value string) {
	cookie := new(http.Cookie)
	cookie.Name = name
	cookie.Value = value
	cookie.HttpOnly = true
	c.(echo.Context).SetCookie(cookie)
}
func (app *CustomMcApp) GetCookie(c interface{}, name string) (string, error) {
	cookie, err := c.(echo.Context).Cookie(name)
	if err != nil {
		return "", err
	}
	return cookie.Value, nil
}
func (app *CustomMcApp) DeleteCookie(c interface{}, name string) {
	cookie, err := c.(echo.Context).Cookie(name)
	if err != nil {
		return
	}
	cookie.Value = ""
	cookie.Expires = time.Unix(0, 0)
	cookie.HttpOnly = true
	c.(echo.Context).SetCookie(cookie)

}
func (app *CustomMcApp) SetSessionCookie(c interface{}, name string, value string) {
	cookie := new(http.Cookie)
	cookie.Name = name
	cookie.Value = value
	cookie.Expires = time.Now().Add(1 * time.Hour)
	cookie.HttpOnly = true
	c.(echo.Context).SetCookie(cookie)
}
func (app *CustomMcApp) SetSessionContext(c interface{}, s *session.Session) {
	c.(echo.Context).Set("session", s)
}
func (app *CustomMcApp) GetConfig() *config.Config {
	return app.Config
}
func (app *CustomMcApp) RedirectLogin(c interface{}, s *session.Session) error {
	return c.(echo.Context).Redirect(http.StatusFound, "/login")
}
func (app *CustomMcApp) RedirectLoginSuccess(c interface{}, s *session.Session) error {
	return c.(echo.Context).Redirect(http.StatusFound, "/app")
}
func (app *CustomMcApp) RenderLogin(c interface{}, s *session.Session) error {
	message := s.ErrorMessage
	s.ErrorMessage = ""
	app.SetSession(s)
	return c.(echo.Context).Render(http.StatusOK, "login.html", map[string]interface{}{
		"message": message,
	})
}
func (app *CustomMcApp) RenderLandingPage(c interface{}, s *session.Session) error {
	return c.(echo.Context).Render(http.StatusOK, "app.html", map[string]interface{}{
		"title":           s.UserInfo.Title,
		"given_name":      s.UserInfo.GivenName,
		"family_name":     s.UserInfo.FamilyName,
		"middle_name":     s.UserInfo.MiddleName,
		"street_address":  s.UserInfo.StreetAddress,
		"city":            s.UserInfo.City,
		"state":           s.UserInfo.State,
		"postal_code":     s.UserInfo.PostalCode,
		"country":         s.UserInfo.Country,
		"email":           s.UserInfo.Email,
		"session_timeout": s.ExpirationTime,
	})
}
func (app *CustomMcApp) Redirect(c interface{}, location *string) error {
	return c.(echo.Context).Redirect(http.StatusFound, *location)
}

func MWJwt(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		app := c.Get("application").(*application.MobileConnectApp)
		s := c.Get("session").(*session.Session)
		log.Println("executing JWT middleware")
		jwtMw := jwt.MiddlewareWithErr(c, s, *app)
		if jwtMw == nil {
			return next(c)
		}
		return (*app).RedirectLogin(c, s)
	}
}

func MWJwtRedirectApp(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		app := c.Get("application").(*application.MobileConnectApp)
		s := c.Get("session").(*session.Session)
		log.Println("executing JWTRedirectApp middleware")
		jwtMw := jwt.Middleware(c, s, *app)
		if jwtMw.Error != nil {
			return next(c)
		}
		return (*app).RedirectLoginSuccess(c, s)
	}
}
func MWClearSession(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		log.Println("executing Clear Session middleware")
		app := c.Get("application").(*application.MobileConnectApp)
		middleware.UseClearSession(c, *app)
		return next(c)
	}
}

func MWSession(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		log.Println("executing Session middleware")
		app := c.Get("application").(*application.MobileConnectApp)
		middleware.UseSession(c, *app)
		return next(c)
	}
}

type ErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func SendError(errorMessage string, errorDescription string) *ErrorResponse {
	return &ErrorResponse{
		Error:            errorMessage,
		ErrorDescription: errorDescription,
	}
}

//middleware for validation
type CustomValidator struct {
	validator *validator.Validate
}

func (cv *CustomValidator) Validate(i interface{}) error {
	return cv.validator.Struct(i)
}

func UseCommonMiddleware(e *echo.Echo) {
	e.Validator = &CustomValidator{validator: validator.New()}

	e.Use(mw.LoggerWithConfig(mw.LoggerConfig{
		Format: "${remote_ip} - - ${time_rfc3339_nano} \"${method} ${uri} ${protocol}\" ${status} ${bytes_out} \"${referer}\" \"${user_agent}\"\n",
	}))
	e.Use(mw.Recover())
}
