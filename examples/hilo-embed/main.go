// Package main is a reference embedding of authlet in a chi-router
// application like Hilo. It is intentionally non-runnable — it depends on
// placeholder app glue (your storage adapter, your user resolver) you
// provide. Treat it as a checklist when wiring authlet into a real chi
// service: AS handler mount, well-known endpoints, JWKS, PRM, and bearer
// middleware on the protected MCP resource.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/eliminyro/authlet/pkg/as"
	"github.com/eliminyro/authlet/pkg/idp"
	"github.com/eliminyro/authlet/pkg/jwt"
	"github.com/eliminyro/authlet/pkg/mcp"
	"github.com/eliminyro/authlet/pkg/rs"
	"github.com/eliminyro/authlet/pkg/storage"
	"github.com/go-chi/chi/v5"
)

// authletStorage is implemented in your app (e.g., hilo/internal/authletstore).
// The placeholder returns nil so the example compiles; a real implementation
// returns a storage.Storage backed by GORM, sqlite, etc.
func authletStorage() storage.Storage { return nil }

// hiloUserResolver maps Google claims to hilo user IDs.
type hiloUserResolver struct{}

// Resolve returns the internal user ID for the upstream OIDC claims. The
// real implementation looks up users by claims.Email.
func (hiloUserResolver) Resolve(_ context.Context, claims idp.Claims) (string, error) {
	// Refuse to map identity on an unverified email — otherwise an upstream
	// account with an unverified address could be mapped onto a user record.
	if !claims.EmailVerified {
		return "", errors.New("hilo-embed: upstream email not verified")
	}
	return "", nil
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
		"https://accounts.google.com",
		"<google-client>",
		"<google-secret>",
		"https://hilo.eliminyro.me/oauth/idp/callback",
		[]string{"openid", "email", "profile"},
	)

	server, _ := as.New(as.Config{
		Issuer:       "https://hilo.eliminyro.me",
		PathPrefix:   "/oauth",
		Upstream:     upstream,
		UserResolver: hiloUserResolver{},
		Storage:      store,
		KeyManager:   mgr,
	})

	prm := mcp.PRM{
		Resource:               "https://hilo.eliminyro.me/api/mcp",
		AuthorizationServers:   []string{"https://hilo.eliminyro.me"},
		BearerMethodsSupported: []string{"header"},
		ScopesSupported:        []string{"mcp"},
	}

	jwksClient := rs.NewJWKSClient("https://hilo.eliminyro.me/.well-known/jwks.json", time.Hour)
	bearer := rs.Middleware(rs.Config{
		ExpectedIssuer:   "https://hilo.eliminyro.me",
		ExpectedAudience: "https://hilo.eliminyro.me/api/mcp",
		JWKS:             jwksClient,
		ResourceMetadata: "https://hilo.eliminyro.me/.well-known/oauth-protected-resource/api/mcp",
	})

	r := chi.NewRouter()
	r.Mount("/oauth", server.Handler())
	r.Get("/.well-known/oauth-authorization-server", server.MetadataHandler)
	r.Get("/.well-known/openid-configuration", server.OIDCMetadataHandler)
	r.Get("/.well-known/jwks.json", server.JWKSHandler)
	r.Get("/.well-known/oauth-protected-resource/api/mcp", mcp.PRMHandler(prm))

	r.With(bearer).Handle("/api/mcp", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("mcp protected"))
	}))

	// RunCleanup starts its own goroutine and returns a done channel;
	// this example discards the channel.
	_ = server.RunCleanup(ctx, time.Hour)

	_ = http.ListenAndServe(":8080", r) //nolint:gosec // example only; no timeouts configured
}
