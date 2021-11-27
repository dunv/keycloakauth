package keycloakauth

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
