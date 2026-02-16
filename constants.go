package keycloakauth

import "github.com/dunv/uhttp"

const (
	CtxKeyKeycloakUser uhttp.ContextKey = "keycloakUser"
	CtxKeyBasicUser uhttp.ContextKey = "basicUser"
)
