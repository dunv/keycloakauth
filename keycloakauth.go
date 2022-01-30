package keycloakauth

import (
	"context"

	"github.com/coreos/go-oidc/v3/oidc"
)

type KeycloakAuth struct {
	// URL under which we can perform a GET request to `.well-kown/openid-configuration`
	// e.g. https://<DOMAIN>:<PORT>/auth/realms/<REALM>
	oauthServerURL string

	// reference to oidc provider (will be initialized
	// by using oauthServerURL when creating a new instance)
	provider *oidc.Provider

	// reference to IDTokenVerifier (will be initialized
	// by using oauthServerURL when creating a new instance)
	idTokenVerifier *oidc.IDTokenVerifier

	// reference to oidc.RemoteKeySet (will be initialized
	// by using oauthServerURL when creating a new instance)
	remoteKeySet *oidc.RemoteKeySet
}

func NewKeycloakAuth(oauthServerURL string) (*KeycloakAuth, error) {
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
		oauthServerURL:  oauthServerURL,
		provider:        provider,
		idTokenVerifier: provider.Verifier(&oidc.Config{}),
		remoteKeySet:    oidc.NewRemoteKeySet(ctx, keycloakWellKnown.JWKSURI),
	}, nil
}
