package keycloakauth

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

type KeycloakAuth struct {
	ctx          context.Context
	serverURL    string
	clientID     string
	clientSecret string

	// oidc
	provider        *oidc.Provider
	idTokenVerifier *oidc.IDTokenVerifier
	remoteKeySet    *oidc.RemoteKeySet

	redirectURL string
}

func NewKeycloakAuth(
	serverURL string,
	clientID string,
	clientSecret string,
	redirectURL string,
) (*KeycloakAuth, error) {
	ctx := context.Background()

	// init oidc lib
	provider, err := oidc.NewProvider(ctx, serverURL)
	if err != nil {
		return nil, err
	}

	// parse some urls from .well-known
	keycloakClaims := KeycloakWellKnown{}
	err = provider.Claims(&keycloakClaims)
	if err != nil {
		return nil, err
	}

	return &KeycloakAuth{
		ctx:             ctx,
		serverURL:       serverURL,
		clientID:        clientID,
		clientSecret:    clientSecret,
		provider:        provider,
		idTokenVerifier: provider.Verifier(&oidc.Config{ClientID: clientID}),
		remoteKeySet:    oidc.NewRemoteKeySet(ctx, keycloakClaims.JWKSURI),
		redirectURL:     redirectURL,
	}, nil
}

var CtxKeyKeycloakUser uhttp.ContextKey = "keycloakUser"

func (k *KeycloakAuth) HandlerMiddleware(u *uhttp.UHTTP) func(next http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			accessToken := strings.Replace(r.Header.Get("Authorization"), "Bearer ", "", 1)

			// Verify that the token is signed by someone we trust
			_, err := k.remoteKeySet.VerifySignature(r.Context(), accessToken)
			if err != nil {
				u.RenderError(w, r, fmt.Errorf("Unauthorized"))
				return
			}

			// Deserialize contents
			token, err := jwt.ParseSigned(accessToken)
			if err != nil {
				u.RenderError(w, r, fmt.Errorf("Unauthorized"))
				return
			}

			// extract claims without verification: verification has been done before
			claims := KeycloakToken{}
			err = token.UnsafeClaimsWithoutVerification(&claims)
			if err != nil {
				u.RenderError(w, r, fmt.Errorf("Unauthorized"))
				return
			}

			// add user to context
			ctx := context.WithValue(r.Context(), CtxKeyKeycloakUser, claims)
			ulog.LogIfError(uhttp.AddLogOutput(w, "authMethod", "jwt"))
			ulog.LogIfError(uhttp.AddLogOutput(w, "user", claims.PreferredUsername))
			next.ServeHTTP(w, r.WithContext(ctx))
		}
	}
}

func UserFromRequest(r *http.Request) KeycloakToken {
	if token, ok := r.Context().Value(CtxKeyKeycloakUser).(KeycloakToken); ok {
		return token
	}
	panic("usage of keycloakUser without registering middleware")
}

func (k *KeycloakAuth) SetupHandlers(u *uhttp.UHTTP) {
	conf := &oauth2.Config{
		ClientID:     k.clientID,
		ClientSecret: k.clientSecret,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		Endpoint:     k.provider.Endpoint(),
		RedirectURL:  k.redirectURL,
	}

	u.Handle("/keycloakauth/login", uhttp.NewHandler(
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

	u.Handle("/keycloakauth/complete", uhttp.NewHandler(
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

}

type KeycloakWellKnown struct {
	Issuer                             string `json:"issuer"`
	AuthorizationEndpoint              string `json:"authorization_endpoint"`
	TokenEndpoint                      string `json:"token_endpoint"`
	IntrospectionEndpoint              string `json:"introspection_endpoint"`
	UserinfoEndpoint                   string `json:"userinfo_endpoint"`
	EndSessionEndpoint                 string `json:"end_session_endpoint"`
	RegistrationEndpoint               string `json:"registration_endpoint"`
	RevocationEndpoint                 string `json:"revocation_endpoint"`
	BackchannelAuthenticationEndpoint  string `json:"backchannel_authentication_endpoint"`
	PushedAuthorizationRequestEndpoint string `json:"pushed_authorization_request_endpoint"`
	DeviceAuthorizationEndpoint        string `json:"device_authorization_endpoint"`
	JWKSURI                            string `json:"jwks_uri"`
}

type KeycloakToken struct {
	AllowedOrigins    []string               `json:"allowed-origins"`
	Email             string                 `json:"email"`
	EmailVerified     bool                   `json:"email_verified"`
	PreferredUsername string                 `json:"preferred_username"`
	RealmAccess       KeycloakAccess         `json:"realm_access"`
	ResourceAccess    KeycloakResourceAccess `json:"resource_access"`
	Scope             string                 `json:"scope"`
}

type KeycloakAccess struct {
	Roles []string `json:"roles"`
}

type KeycloakResourceAccess map[string]KeycloakAccess
