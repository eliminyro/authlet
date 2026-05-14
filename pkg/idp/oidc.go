package idp

import (
	"context"
	"errors"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDCProvider is a configured upstream OIDC issuer. It pairs a verifier for
// inbound ID tokens with an oauth2 config used to drive the authorization
// code flow.
type OIDCProvider struct {
	issuer       string
	verifier     *oidc.IDTokenVerifier
	oauth2Config *oauth2.Config
}

// NewOIDC discovers the issuer's metadata and returns a configured provider.
func NewOIDC(ctx context.Context, issuerURL, clientID, clientSecret, redirectURL string, scopes []string) (*OIDCProvider, error) {
	prov, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}
	return &OIDCProvider{
		issuer:   issuerURL,
		verifier: prov.Verifier(&oidc.Config{ClientID: clientID}),
		oauth2Config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint:     prov.Endpoint(),
			RedirectURL:  redirectURL,
			Scopes:       scopes,
		},
	}, nil
}

// AuthURL returns the upstream authorize URL for the given state.
func (p *OIDCProvider) AuthURL(state string) string {
	return p.oauth2Config.AuthCodeURL(state, oauth2.AccessTypeOnline)
}

// Exchange exchanges an upstream authorization code for an ID token and
// returns the parsed claims.
func (p *OIDCProvider) Exchange(ctx context.Context, code string) (Claims, error) {
	tok, err := p.oauth2Config.Exchange(ctx, code)
	if err != nil {
		return Claims{}, fmt.Errorf("token exchange: %w", err)
	}
	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok {
		return Claims{}, errors.New("idp: id_token missing in upstream response")
	}
	idTok, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return Claims{}, fmt.Errorf("id token verify: %w", err)
	}
	var raw map[string]any
	if err := idTok.Claims(&raw); err != nil {
		return Claims{}, fmt.Errorf("id token claims: %w", err)
	}
	return Claims{
		Issuer:        idTok.Issuer,
		Subject:       idTok.Subject,
		Email:         asString(raw["email"]),
		EmailVerified: asBool(raw["email_verified"]),
		Name:          asString(raw["name"]),
		Picture:       asString(raw["picture"]),
		Raw:           raw,
	}, nil
}

// Issuer returns the upstream issuer URL this provider was configured with.
func (p *OIDCProvider) Issuer() string { return p.issuer }

func asString(v any) string { s, _ := v.(string); return s }
func asBool(v any) bool     { b, _ := v.(bool); return b }
