// Package main is a reference embedding of authlet in a stdlib
// http.ServeMux application like Memory MCP, with dual-auth (API key OR
// Bearer JWT) on /mcp. It is intentionally non-runnable — it depends on
// placeholder app glue (your storage adapter, your user resolver, your
// legacy API-key validator) you provide. Treat it as a checklist when
// wiring authlet into a real stdlib-mux service that must keep its
// existing API-key auth while accepting OAuth-issued JWTs.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/eliminyro/authlet/pkg/as"
	"github.com/eliminyro/authlet/pkg/idp"
	"github.com/eliminyro/authlet/pkg/jwt"
	"github.com/eliminyro/authlet/pkg/mcp"
	"github.com/eliminyro/authlet/pkg/rs"
	"github.com/eliminyro/authlet/pkg/storage"
)

// authletStorage is implemented in your app (e.g., memory/internal/authletstore).
// The placeholder returns nil so the example compiles.
func authletStorage() storage.Storage { return nil }

// memoryUserResolver maps upstream OIDC claims (from Hilo's authlet) to
// memory-mcp tenant user IDs.
type memoryUserResolver struct{}

// Resolve looks up tenant_users by claims.Email and returns tenant_users.id
// as user_id. The placeholder returns the empty string.
func (memoryUserResolver) Resolve(_ context.Context, claims idp.Claims) (string, error) {
	// Refuse to map identity on an unverified email: an attacker who controls
	// an upstream account with an unverified address could otherwise be mapped
	// onto another user's tenant record. Fail closed.
	if !claims.EmailVerified {
		return "", errors.New("memory-embed: upstream email not verified")
	}
	// Look up tenant_users by claims.Email. Return tenant_users.id as user_id.
	return "", nil
}

// apiKeyValidator validates a legacy API key carried on the request and
// reports whether the caller is authenticated. Implement it in your app; the
// placeholder below rejects everything so the example fails closed until a
// real validator is wired in.
type apiKeyValidator func(r *http.Request) bool

// legacyAPIKey is your existing API-key check. The placeholder returns false:
// until you supply a real validator, requests without a valid Bearer JWT are
// rejected rather than served unauthenticated.
func legacyAPIKey(_ *http.Request) bool { return false }

// dualAuth runs the bearer middleware when the request carries an
// Authorization: Bearer header, and otherwise requires the legacy API-key
// validator to accept the request. It NEVER falls through to the protected
// handler unauthenticated: a request with neither a valid Bearer JWT nor a
// valid API key gets a 401. This lets a service migrate to OAuth without
// breaking existing API-key clients, while failing closed.
func dualAuth(bearer func(http.Handler) http.Handler, validateAPIKey apiKeyValidator, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Bearer path: the RS middleware validates the JWT and writes its own
		// 401 + WWW-Authenticate on failure. The scheme name is
		// case-insensitive (RFC 7235), so match it without slicing.
		if h := r.Header.Get("Authorization"); strings.HasPrefix(strings.ToLower(h), "bearer ") {
			bearer(next).ServeHTTP(w, r)
			return
		}
		// Legacy API-key path: an explicit, validated branch. Fail closed if
		// no validator is configured or it rejects the request.
		if validateAPIKey != nil && validateAPIKey(r) {
			next.ServeHTTP(w, r)
			return
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
}

func main() {
	ctx := context.Background()

	// Load the AES-GCM master key from the environment. In production, source
	// this from a secrets manager (Vault, GCP Secret Manager, ...) rather than
	// a raw env var. It MUST be exactly 32 bytes: a changed key silently
	// rotates every signing key and invalidates all live tokens, so fail
	// closed if it is missing or the wrong length — never fall back to a
	// literal or an ephemeral key.
	masterKey := []byte(os.Getenv("AUTHLET_MASTER_KEY"))
	if len(masterKey) != 32 {
		log.Fatal("AUTHLET_MASTER_KEY must be set to a 32-byte key")
	}

	store := authletStorage()
	mgr := jwt.NewManager(store.SigningKeys(), masterKey)
	_ = mgr.Bootstrap(ctx)

	upstream, _ := idp.NewOIDC(
		ctx,
		"https://hilo.eliminyro.me",
		"memory-mcp",
		"<secret>",
		"https://memory-mcp.a11s.dev/oauth/idp/callback",
		[]string{"openid", "email", "profile"},
	)

	server, _ := as.New(as.Config{
		Issuer:       "https://memory-mcp.a11s.dev",
		PathPrefix:   "/oauth",
		Upstream:     upstream,
		UserResolver: memoryUserResolver{},
		Storage:      store,
		KeyManager:   mgr,
		AdditionalClaims: func(_, _, _ string) map[string]any {
			// Look up tenant_id from tenant_users.id == userID and emit it.
			return map[string]any{"tenant_id": "<looked up>"}
		},
	})

	jwksClient := rs.NewJWKSClient("https://memory-mcp.a11s.dev/.well-known/jwks.json", time.Hour)
	bearer := rs.Middleware(rs.Config{
		ExpectedIssuer:   "https://memory-mcp.a11s.dev",
		ExpectedAudience: "https://memory-mcp.a11s.dev/mcp",
		JWKS:             jwksClient,
		ResourceMetadata: "https://memory-mcp.a11s.dev/.well-known/oauth-protected-resource/mcp",
	})

	mux := http.NewServeMux()
	mux.Handle("/oauth/", http.StripPrefix("/oauth", server.Handler()))
	mux.HandleFunc("/.well-known/oauth-authorization-server", server.MetadataHandler)
	mux.HandleFunc("/.well-known/openid-configuration", server.OIDCMetadataHandler)
	mux.HandleFunc("/.well-known/jwks.json", server.JWKSHandler)
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", mcp.PRMHandler(mcp.PRM{
		Resource:               "https://memory-mcp.a11s.dev/mcp",
		AuthorizationServers:   []string{"https://memory-mcp.a11s.dev"},
		BearerMethodsSupported: []string{"header"},
		ScopesSupported:        []string{"mcp"},
	}))

	mcpHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("mcp"))
	})
	mux.Handle("/mcp", dualAuth(bearer, legacyAPIKey, mcpHandler))
	mux.Handle("/mcp/", dualAuth(bearer, legacyAPIKey, mcpHandler))

	// RunCleanup spawns its own goroutine; discard the done channel.
	_ = server.RunCleanup(ctx, time.Hour)
	_ = http.ListenAndServe(":8090", mux) //nolint:gosec // example only; no timeouts configured
}
