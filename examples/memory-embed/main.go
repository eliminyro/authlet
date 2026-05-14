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
	"net/http"
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
func (memoryUserResolver) Resolve(_ context.Context, _ idp.Claims) (string, error) {
	// Look up tenant_users by claims.Email. Return tenant_users.id as user_id.
	return "", nil
}

// dualAuth runs the bearer middleware when the request carries an
// Authorization: Bearer header, and otherwise falls through to the legacy
// API-key validator (not shown). This lets a service migrate to OAuth
// without breaking existing API-key clients.
func dualAuth(bearer func(http.Handler) http.Handler, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// If Authorization: Bearer is set, run the bearer middleware.
		// Otherwise fall back to existing API-key middleware (not shown).
		if h := r.Header.Get("Authorization"); len(h) > 7 && h[:7] == "Bearer " {
			bearer(next).ServeHTTP(w, r)
			return
		}
		// fallback to legacy API-key validator here
		next.ServeHTTP(w, r)
	})
}

func main() {
	ctx := context.Background()
	masterKey := []byte("THIRTY-TWO-BYTES-OF-MASTER-KEY!!")

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
	mux.Handle("/mcp", dualAuth(bearer, mcpHandler))
	mux.Handle("/mcp/", dualAuth(bearer, mcpHandler))

	// RunCleanup spawns its own goroutine; discard the done channel.
	_ = server.RunCleanup(ctx, time.Hour)
	_ = http.ListenAndServe(":8090", mux) //nolint:gosec // example only; no timeouts configured
}
