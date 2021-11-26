package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/dunv/uhttp"
	"github.com/dunv/ulog"
	"github.com/google/uuid"
	"golang.org/x/oauth2"

	jwt "gopkg.in/square/go-jose.v2/jwt"
)

var ISSUER = "https://keycloak.unverricht.net/auth/realms/Unverricht"

func main() {
	ctx := context.Background()

	// Discover endpoints using openID connect standard
	provider, err := oidc.NewProvider(ctx, ISSUER)
	if err != nil {
		ulog.Fatal(err)
	}

	// Extract additional information from provider
	keycloakClaims := KeycloakClaims{}
	err = provider.Claims(&keycloakClaims)
	if err != nil {
		ulog.Fatal(err)
	}

	// Obtain verifier
	jwks := oidc.NewRemoteKeySet(ctx, keycloakClaims.JWKSURI)

	// Init oauth with discovered endpoints
	conf := &oauth2.Config{
		ClientID:     "brauen",
		ClientSecret: "2e54f99f-60b6-428c-baa4-e185c01a3559",
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		Endpoint:     provider.Endpoint(),
		RedirectURL:  "http://localhost:8080/auth/complete",
	}

	// Init verifier
	verifier := provider.Verifier(&oidc.Config{ClientID: conf.ClientID})

	u := uhttp.NewUHTTP(
		uhttp.WithSendPanicInfoToClient(true),
		uhttp.WithGranularLogging(false, true, false),
	)

	u.Handle("/auth/login", uhttp.NewHandler(
		uhttp.WithGet(func(r *http.Request, returnCode *int) interface{} {
			w := r.Context().Value(uhttp.CtxKeyResponseWriter).(http.ResponseWriter)

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

	u.Handle("/auth/complete", uhttp.NewHandler(
		uhttp.WithGet(func(r *http.Request, returnCode *int) interface{} {
			// Verify state
			// compare value in get-request (from redirect) to value saved in cookie
			stateCookie, err := r.Cookie("state")
			if err != nil {
				return errors.New("stateCookie not found")
			}
			if r.URL.Query().Get("state") != stateCookie.Value {
				return errors.New("state-cookie and state from redirect do not match")
			}

			// Exchange code with token (talking to oAuth server)
			token, err := conf.Exchange(ctx, r.URL.Query().Get("code"))
			if err != nil {
				return err
			}

			// Extract, parse and validate id_token (according to oidc spec)
			rawIDToken, ok := token.Extra("id_token").(string)
			if !ok {
				return fmt.Errorf("could not extract id_token")
			}
			idToken, err := verifier.Verify(ctx, rawIDToken)
			if err != nil {
				return fmt.Errorf("could not verify id_token")
			}

			// Verify nonce
			// compare value saved in cookie with value encoded in id_token
			nonceCookie, err := r.Cookie("nonce")
			if err != nil {
				return errors.New("nonceCookie not found")
			}
			if idToken.Nonce != nonceCookie.Value {
				return errors.New("nonce-cookie and id_token.nonce do not match")
			}

			return map[string]interface{}{
				"refresh_token": token.RefreshToken,
				"access_token":  token.AccessToken,
			}
		}),
	))

	u.Handle("/api", uhttp.NewHandler(
		uhttp.WithGet(func(r *http.Request, returnCode *int) interface{} {
			accessToken := strings.Replace(r.Header.Get("Authorization"), "Bearer ", "", 1)

			// Verify that the token is signed by someone we trust
			_, err := jwks.VerifySignature(ctx, accessToken)
			if err != nil {
				return err
			}

			// Deserialize contents
			token, err := jwt.ParseSigned(accessToken)
			if err != nil {
				return err
			}

			// extract claims without verification: verification has been done before
			claims := make(map[string]interface{})
			err = token.UnsafeClaimsWithoutVerification(&claims)
			if err != nil {
				return err
			}

			return claims
		}),
	))

	ulog.FatalIfError(u.ListenAndServe())
}
