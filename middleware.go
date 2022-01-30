package keycloakauth

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/dunv/uhelpers"
	"github.com/dunv/uhttp"
	"github.com/dunv/ulog"
	jwt "gopkg.in/square/go-jose.v2/jwt"
)

var CtxKeyKeycloakUser uhttp.ContextKey = "keycloakUser"

// Require user authentication for this handler
// If a hasAccessFn is passed it will also perform authorization
func (k *KeycloakAuth) RequireAuth(u *uhttp.UHTTP, hasAccessFns ...HasAccessFn) func(next http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			token, err := k.TokenFromRequest(r)
			if err != nil {
				ulog.Tracef("Could not get TokenFromRequest (%s)", err)
				u.RenderError(w, r, fmt.Errorf("Unauthorized"))
				return
			}

			// go through all accessFns and check if any one of them grants access.
			// If no function is defined: no further authorization is needed
			accessGranted := len(hasAccessFns) == 0
			for _, hasAccessFn := range hasAccessFns {
				if hasAccessFn(*token) {
					accessGranted = true
					break
				}
			}

			if !accessGranted {
				ulog.Tracef("Unauthorized: user does not have access to resource")
				u.RenderError(w, r, fmt.Errorf("Unauthorized"))
				return
			}

			// add user to context
			ctx := context.WithValue(r.Context(), CtxKeyKeycloakUser, *token)
			ulog.LogIfError(uhttp.AddLogOutput(w, "authMethod", "jwt"))
			ulog.LogIfError(uhttp.AddLogOutput(w, "user", token.PreferredUsername))
			next.ServeHTTP(w, r.WithContext(ctx))
		}
	}
}

// Add user information if it is there. If not, just continue
func (k *KeycloakAuth) OptionalAuth(u *uhttp.UHTTP) func(next http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			token, err := k.TokenFromRequest(r)
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}

			// add user to context
			ctx := context.WithValue(r.Context(), CtxKeyKeycloakUser, *token)
			ulog.LogIfError(uhttp.AddLogOutput(w, "authMethod", "jwt"))
			ulog.LogIfError(uhttp.AddLogOutput(w, "user", token.PreferredUsername))
			next.ServeHTTP(w, r.WithContext(ctx))
		}
	}
}

// Get token from context if RequireAuth middleware has been added to handler
// Will not consume resources unnecessarily
func TokenFromContext(ctx context.Context) KeycloakToken {
	if token, ok := ctx.Value(CtxKeyKeycloakUser).(KeycloakToken); ok {
		return token
	}
	panic("usage of keycloakUser without registering middleware")
}

// Get token from request if RequireAuth middleware has been added to handler
// Will not consume resources unnecessarily
func TokenFromRequest(r *http.Request) KeycloakToken {
	return TokenFromContext(r.Context())
}

// Get token from request without middleware. Will execute all required JWT parsing
func (k *KeycloakAuth) TokenFromRequest(r *http.Request) (*KeycloakToken, error) {
	// Get Token from header
	accessToken := strings.Replace(r.Header.Get("Authorization"), "Bearer ", "", 1)

	// Verify that the token is signed by someone we trust
	_, err := k.remoteKeySet.VerifySignature(r.Context(), accessToken)
	if err != nil {
		return nil, fmt.Errorf("Unauthorized: could not verify signature (%s)", err)
	}

	// Deserialize contents
	token, err := jwt.ParseSigned(accessToken)
	if err != nil {
		return nil, fmt.Errorf("Unauthorized: could not parse token (%s)", err)
	}

	// extract claims without verification: verification has been done before
	claims := KeycloakToken{}
	err = token.UnsafeClaimsWithoutVerification(&claims)
	if err != nil {
		return nil, fmt.Errorf("Unauthorized: could not extract claims from token (%s)", err)
	}

	return &claims, nil
}

func (k *KeycloakAuth) Permission(fn ...HasAccessFn) func(*http.Request) bool {
	return func(r *http.Request) bool {
		token, err := k.TokenFromRequest(r)
		if err != nil {
			ulog.Trace(err)
			return false
		}
		accessGranted := len(fn) == 0
		for _, hasAccessFn := range fn {
			if hasAccessFn(*token) {
				accessGranted = true
				break
			}
		}
		return accessGranted
	}
}

type HasAccessFn func(KeycloakToken) bool

func LimitAccessToOr(resource string, roles ...string) HasAccessFn {
	return func(t KeycloakToken) bool {
		if resource, ok := t.ResourceAccess[resource]; ok {
			for _, role := range resource.Roles {
				if uhelpers.SliceContainsItem(roles, role) {
					return true
				}
			}
		}
		return false
	}
}
