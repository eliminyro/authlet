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

// AuthURL returns the upstream authorize URL for the given state, binding
// a per-flow nonce and a PKCE S256 challenge derived from codeVerifier.
// The nonce defends the upstream login leg against authorization-code
// injection (OIDC Core §3.1.2.1); the PKCE challenge binds the upstream
// code to the verifier presented at Exchange (OAuth 2.1 §7.6). Empty
// nonce / codeVerifier arguments are omitted so a zero-config test
// provider still produces a URL.
func (p *OIDCProvider) AuthURL(state, nonce, codeVerifier string) string {
	opts := []oauth2.AuthCodeOption{oauth2.AccessTypeOnline}
	if nonce != "" {
		opts = append(opts, oauth2.SetAuthURLParam("nonce", nonce))
	}
	if codeVerifier != "" {
		opts = append(opts, oauth2.S256ChallengeOption(codeVerifier))
	}
	return p.oauth2Config.AuthCodeURL(state, opts...)
}

// Exchange exchanges an upstream authorization code for an ID token and
// returns the parsed claims. codeVerifier completes the PKCE handshake
// begun by AuthURL, and expectedNonce is matched byte-for-byte against
// the id_token's nonce claim: a missing or mismatched nonce fails the
// exchange, closing the upstream authorization-code injection vector
// (OIDC Core §3.1.3.7).
func (p *OIDCProvider) Exchange(ctx context.Context, code, codeVerifier, expectedNonce string) (Claims, error) {
	opts := []oauth2.AuthCodeOption{}
	if codeVerifier != "" {
		opts = append(opts, oauth2.VerifierOption(codeVerifier))
	}
	tok, err := p.oauth2Config.Exchange(ctx, code, opts...)
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
	// Validate the per-flow nonce. The go-oidc verifier checks signature,
	// issuer, audience and expiry but NOT nonce, so this is the only gate
	// against a replayed/injected upstream code.
	if asString(raw["nonce"]) != expectedNonce {
		return Claims{}, errors.New("idp: id_token nonce mismatch")
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

// NewForTest is a test-only helper that constructs an OIDCProvider with
// stub-but-non-nil internals so it satisfies Configured() without doing
// network discovery. Use from external test packages only.
func NewForTest(issuerURL string) *OIDCProvider {
	return &OIDCProvider{
		issuer:       issuerURL,
		verifier:     &oidc.IDTokenVerifier{},
		oauth2Config: &oauth2.Config{},
	}
}

// Configured reports whether the provider was constructed via NewOIDC.
// A zero-valued *OIDCProvider is not configured and will panic if used,
// so callers (notably as.Config.validate) check this rather than just a
// nil pointer.
func (p *OIDCProvider) Configured() bool {
	return p != nil && p.verifier != nil && p.oauth2Config != nil
}

func asString(v any) string { s, _ := v.(string); return s }
func asBool(v any) bool     { b, _ := v.(bool); return b }
