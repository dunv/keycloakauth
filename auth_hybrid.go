package keycloakauth

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"

	"github.com/dunv/uhttp"
)

func (k *KeycloakAuth) AuthHybrid(
u *uhttp.UHTTP,
	authBasicCredentials map[string]string,
 	hasAccessFns ...HasAccessFn,
) uhttp.Middleware {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			// check basic-auth, which is cheaper to calculate
			if requestUser, requestPassword, ok := r.BasicAuth(); ok {
				requestPasswordSha256 := fmt.Sprintf("%x", sha256.Sum256([]byte(requestPassword)))
				if ok {
					for allowedUser, allowedPasswordSha256 := range authBasicCredentials {
						if requestUser == allowedUser && requestPasswordSha256 == allowedPasswordSha256 {
							ctx := context.WithValue(r.Context(), CtxKeyBasicUser, allowedUser)
							_ = uhttp.AddLogOutput(w, "user", allowedUser)           // if we are using websockets this returns an error which we want to ignore
							next.ServeHTTP(w, r.WithContext(ctx))
							return
						}
					}
				}
			}

			// "copy-paste" of RequireAuth
			token, err := k.TokenFromRequest(r)
			if err != nil {
				// ulog.Tracef("Could not get TokenFromRequest (%s)", err)
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
				// ulog.Tracef("Unauthorized: user does not have access to resource")
				u.RenderError(w, r, fmt.Errorf("Unauthorized"))
				return
			}

			// add user to context
			ctx := context.WithValue(r.Context(), CtxKeyKeycloakUser, *token)
			if err := uhttp.AddLogOutput(w, "authMethod", "jwt"); err != nil {
				u.Log().Errorf("could not add log output: %s", err)
			}
			if err := uhttp.AddLogOutput(w, "user", token.PreferredUsername); err != nil {
				u.Log().Errorf("could not add log output: %s", err)
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		}
	}
}
