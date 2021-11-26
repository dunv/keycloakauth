package main

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc"
	"github.com/davecgh/go-spew/spew"
	"github.com/dgrijalva/jwt-go"
	"github.com/dunv/uhttp"
	"github.com/dunv/ulog"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
)

func main() {

	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, "https://keycloak.unverricht.net/auth/realms/unverricht/protocol/openid-connect")
	if err != nil {
		// handle error
	}

	conf := &oauth2.Config{
		ClientID:     "brauen",
		ClientSecret: "2e54f99f-60b6-428c-baa4-e185c01a3559",
		Scopes:       []string{"email", "openid"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://keycloak.unverricht.net/auth/realms/unverricht/protocol/openid-connect/auth",
			TokenURL: "https://keycloak.unverricht.net/auth/realms/unverricht/protocol/openid-connect/token",
		},
		RedirectURL: "http://localhost:8080/auth/complete",
	}
	nonce := uuid.New().String()

	res, err := http.Get("https://keycloak.unverricht.net/auth/realms/unverricht/.well-known/openid-configuration")
	if err != nil {
		ulog.Fatal(err)
	}

	u := uhttp.NewUHTTP(uhttp.WithSendPanicInfoToClient(true))

	u.Handle("/auth/complete", uhttp.NewHandler(
		uhttp.WithOptionalGet(uhttp.R{
			"state":         uhttp.STRING,
			"session_state": uhttp.STRING,
			"code":          uhttp.STRING,
			"error":         uhttp.STRING,
		}),
		uhttp.WithGet(func(r *http.Request, returnCode *int) interface{} {
			getErr := uhttp.GetAsString("error", r)
			if getErr != nil && *getErr != "" {
				return errors.New(*getErr)
			}

			state := uhttp.GetAsString("state", r)
			sessionState := uhttp.GetAsString("session_state", r)
			code := uhttp.GetAsString("code", r)
			token, err := conf.Exchange(ctx, *code)
			if err != nil {
				return err
			}

			return map[string]interface{}{
				"state":         *state,
				"session_state": *sessionState,
				"code":          *code,
				"token":         token,
			}
		}),
	))

	u.Handle("/auth/login", uhttp.NewHandler(
		uhttp.WithGet(func(r *http.Request, returnCode *int) interface{} {
			w := r.Context().Value(uhttp.CtxKeyResponseWriter).(http.ResponseWriter)
			url := conf.AuthCodeURL(nonce, oauth2.AccessTypeOffline)
			http.Redirect(w, r, url, http.StatusPermanentRedirect)
			return nil
		}),
	))

	u.Handle("/api", uhttp.NewHandler(
		uhttp.WithGet(func(r *http.Request, returnCode *int) interface{} {
			authParts := strings.Split(r.Header.Get("Authorization"), "Bearer ")
			if len(authParts) != 2 {
				return errors.New("could not parse Authorization Header")
			}

			accessToken := authParts[1]

			token, err := jwt.Parse(accessToken, func(t *jwt.Token) (interface{}, error) {
				spew.Dump(t)
				return nil, errors.New("test")
			})
			if err != nil {
				return errors.New("could not parse accessToken")
			}
			return token
		}),
	))

	// client := conf.Client(ctx, tok)
	// res, err := client.Post("https://keycloak.unverricht.net/auth/realms/unverricht/protocol/openid-connect/token/introspect", "application/json", nil)
	// if err != nil
	// 	ulog.Fatal(err)
	// }

	ulog.FatalIfError(u.ListenAndServe())
}
