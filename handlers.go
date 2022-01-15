package keycloakauth

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/dunv/uhttp"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
)

func (k *KeycloakAuth) SetupHandlers(u *uhttp.UHTTP, redirectURL string) {
	conf := &oauth2.Config{
		ClientID:     k.clientID,
		ClientSecret: k.clientSecret,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		Endpoint:     k.provider.Endpoint(),
		RedirectURL:  fmt.Sprintf("%s/keycloakauth/complete", strings.TrimSuffix(redirectURL, "/")),
	}

	u.Handle("/keycloakauth/login", uhttp.NewHandler(
		uhttp.WithRequiredGet(uhttp.R{
			"redirectUrl": uhttp.STRING,
		}),
		uhttp.WithGet(func(r *http.Request, returnCode *int) interface{} {
			w := r.Context().Value(uhttp.CtxKeyResponseWriter).(http.ResponseWriter)
			redirectURL := uhttp.GetAsString("redirectUrl", r)

			// save client's specific redirect url
			http.SetCookie(w, &http.Cookie{
				Name:     "redirect-url",
				Value:    *redirectURL,
				MaxAge:   int(time.Hour.Seconds()),
				Secure:   r.TLS != nil,
				HttpOnly: true,
			})

			// create and set state in client
			state := uuid.New().String()
			stateCookie := &http.Cookie{
				Name:     "state",
				Value:    state,
				MaxAge:   int(time.Hour.Seconds()),
				Secure:   r.TLS != nil,
				HttpOnly: true,
			}
			http.SetCookie(w, stateCookie)

			// create and set nonce in client
			nonce := uuid.New().String()
			nonceCookie := &http.Cookie{
				Name:     "nonce",
				Value:    nonce,
				MaxAge:   int(time.Hour.Seconds()),
				Secure:   r.TLS != nil,
				HttpOnly: true,
			}
			http.SetCookie(w, nonceCookie)

			// redirect user
			http.Redirect(w, r, conf.AuthCodeURL(state, oidc.Nonce(nonce)), http.StatusFound)
			return nil
		}),
	))

	u.Handle("/keycloakauth/complete", uhttp.NewHandler(
		uhttp.WithGet(func(r *http.Request, returnCode *int) interface{} {
			w := r.Context().Value(uhttp.CtxKeyResponseWriter).(http.ResponseWriter)

			// Verify state
			// compare value in get-request (from redirect) to value saved in cookie
			stateCookie, err := r.Cookie("state")
			if err != nil {
				return errors.New("state-cookie not found")
			}
			if r.URL.Query().Get("state") != stateCookie.Value {
				return errors.New("state-cookie and state from redirect do not match")
			}

			// Exchange code with token (talking to oAuth server)
			token, err := conf.Exchange(r.Context(), r.URL.Query().Get("code"))
			if err != nil {
				return err
			}

			// Extract, parse and validate id_token (according to oidc spec)
			rawIDToken, ok := token.Extra("id_token").(string)
			if !ok {
				return fmt.Errorf("could not extract id_token")
			}
			idToken, err := k.idTokenVerifier.Verify(r.Context(), rawIDToken)
			if err != nil {
				return fmt.Errorf("could not verify id_token")
			}

			// Verify nonce
			// compare value saved in cookie with value encoded in id_token
			nonceCookie, err := r.Cookie("nonce")
			if err != nil {
				return errors.New("nonce-cookie not found")
			}
			if idToken.Nonce != nonceCookie.Value {
				return errors.New("nonce-cookie and id_token.nonce do not match")
			}

			redirectURL, err := r.Cookie("redirect-url")
			if err != nil {
				return errors.New("redirect-url-cookie not found")
			}

			idTokenClaims := map[string]interface{}{}
			if err := idToken.Claims(&idTokenClaims); err != nil {
				return fmt.Errorf("could not parse idToken (%s)", err)
			}

			http.Redirect(w, r,
				fmt.Sprintf("%s?access_token=%s&refresh_token=%s&id_token=%s",
					redirectURL.Value,
					token.AccessToken,
					token.RefreshToken,
					rawIDToken,
				),
				http.StatusFound,
			)
			return nil
		}),
	))
}
