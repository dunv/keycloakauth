package keycloakauth

import (
	"context"

	"github.com/coreos/go-oidc/v3/oidc"
)

type KeycloakAuth struct {
	ctx            context.Context
	oauthServerURL string
	clientID       string
	clientSecret   string

	// oidc
	provider        *oidc.Provider
	idTokenVerifier *oidc.IDTokenVerifier
	remoteKeySet    *oidc.RemoteKeySet

	apiURL string
}

func NewKeycloakAuth(
	// URL under which we can perform a GET request to `.well-kown/openid-configuration`
	// e.g. https://<DOMAIN>:<PORT>/auth/realms/<REALM>
	oauthServerURL string,
	// ClientID as registered in Keycloak
	clientID string,
	// ClientSecret as registered in Keycloak
	clientSecret string,
	// URL under which this API runs (this will be used to construct the redirect_uri)
	apiURL string,
) (*KeycloakAuth, error) {
	ctx := context.Background()

	// init oidc lib
	provider, err := oidc.NewProvider(ctx, oauthServerURL)
	if err != nil {
		return nil, err
	}

	// parse some urls from .well-known
	keycloakWellKnown := KeycloakWellKnown{}
	err = provider.Claims(&keycloakWellKnown)
	if err != nil {
		return nil, err
	}

	return &KeycloakAuth{
		ctx:             ctx,
		oauthServerURL:  oauthServerURL,
		clientID:        clientID,
		clientSecret:    clientSecret,
		provider:        provider,
		idTokenVerifier: provider.Verifier(&oidc.Config{ClientID: clientID}),
		remoteKeySet:    oidc.NewRemoteKeySet(ctx, keycloakWellKnown.JWKSURI),
		apiURL:          apiURL,
	}, nil
}
