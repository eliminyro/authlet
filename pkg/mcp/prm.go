// Package mcp provides Model Context Protocol-flavored helpers on top of
// authlet's AS. Currently:
//
//   - PRM (RFC 9728 Protected Resource Metadata) JSON handler
//   - WWW-Authenticate challenge string with resource_metadata pointer
package mcp

import (
	"encoding/json"
	"net/http"
)

// PRM is the Protected Resource Metadata JSON document defined by RFC 9728.
// It advertises which authorization servers can issue tokens for the
// resource and which bearer methods and scopes the resource accepts.
type PRM struct {
	// Resource is the canonical URL of the protected resource.
	Resource string `json:"resource"`
	// AuthorizationServers lists the issuer URLs that may mint tokens for
	// this resource.
	AuthorizationServers []string `json:"authorization_servers"`
	// BearerMethodsSupported enumerates how clients may present bearer
	// tokens (e.g. "header", "body", "query"). Optional.
	BearerMethodsSupported []string `json:"bearer_methods_supported,omitempty"`
	// ScopesSupported lists scope values the resource recognises. Optional.
	ScopesSupported []string `json:"scopes_supported,omitempty"`
}

// PRMHandler returns an http.HandlerFunc that serves the given PRM document
// as JSON with a public Cache-Control header. Mount it at the
// .well-known/oauth-protected-resource path appropriate for the resource.
func PRMHandler(p PRM) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		_ = json.NewEncoder(w).Encode(p)
	}
}
