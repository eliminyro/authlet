package as

import (
	"encoding/json"
	"net/http"
)

// ASMetadata is the RFC 8414 document.
type ASMetadata struct {
	// Issuer is the public base URL.
	Issuer string `json:"issuer"`
	// AuthorizationEndpoint is the absolute URL of /authorize.
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	// TokenEndpoint is the absolute URL of /token.
	TokenEndpoint string `json:"token_endpoint"`
	// RegistrationEndpoint is the absolute URL of /register.
	RegistrationEndpoint string `json:"registration_endpoint"`
	// RevocationEndpoint is the absolute URL of /revoke.
	RevocationEndpoint string `json:"revocation_endpoint"`
	// UserinfoEndpoint is the absolute URL of /userinfo.
	UserinfoEndpoint string `json:"userinfo_endpoint,omitempty"`
	// JWKSURI is the absolute URL of /.well-known/jwks.json.
	JWKSURI string `json:"jwks_uri"`
	// ScopesSupported lists scopes the server understands.
	ScopesSupported []string `json:"scopes_supported"`
	// ResponseTypesSupported lists response_type values accepted at /authorize.
	ResponseTypesSupported []string `json:"response_types_supported"`
	// GrantTypesSupported lists grant_type values accepted at /token.
	GrantTypesSupported []string `json:"grant_types_supported"`
	// CodeChallengeMethodsSupported lists PKCE methods accepted at /authorize.
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
	// TokenEndpointAuthMethodsSupported lists client auth methods at /token.
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	// IDTokenSigningAlgValuesSupported lists ID token signing algorithms.
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported,omitempty"`
	// SubjectTypesSupported lists OIDC subject types.
	SubjectTypesSupported []string `json:"subject_types_supported,omitempty"`
}

func (a *AS) metadata() ASMetadata {
	base := a.cfg.Issuer
	p := base + a.cfg.PathPrefix
	return ASMetadata{
		Issuer:                            base,
		AuthorizationEndpoint:             p + "/authorize",
		TokenEndpoint:                     p + "/token",
		RegistrationEndpoint:              p + "/register",
		RevocationEndpoint:                p + "/revoke",
		UserinfoEndpoint:                  p + "/userinfo",
		JWKSURI:                           base + "/.well-known/jwks.json",
		ScopesSupported:                   []string{"mcp"},
		ResponseTypesSupported:            []string{"code"},
		GrantTypesSupported:               []string{"authorization_code", "refresh_token"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		TokenEndpointAuthMethodsSupported: []string{"none", "client_secret_basic"},
		IDTokenSigningAlgValuesSupported:  []string{"RS256"},
		SubjectTypesSupported:             []string{"public"},
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
