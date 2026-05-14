// authletd is a standalone authlet AS for development and integration
// testing. It uses the in-memory storage backend; restart wipes state.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/eliminyro/authlet/pkg/as"
	"github.com/eliminyro/authlet/pkg/idp"
	"github.com/eliminyro/authlet/pkg/jwt"
	"github.com/eliminyro/authlet/pkg/mcp"
	"github.com/eliminyro/authlet/pkg/storage/memstore"
)

func main() {
	var (
		addr           = flag.String("addr", ":8089", "listen address")
		issuer         = flag.String("issuer", "http://localhost:8089", "issuer URL")
		upstreamIssuer = flag.String("upstream-issuer", "", "upstream OIDC issuer URL (required)")
		upstreamClient = flag.String("upstream-client-id", "", "upstream OIDC client id")
		upstreamSecret = flag.String("upstream-client-secret", "", "upstream OIDC client secret")
		upstreamRedir  = flag.String("upstream-redirect", "", "upstream OIDC redirect URI (e.g. <issuer>/oauth/idp/callback)")
		prmResource    = flag.String("prm-resource", "", "if set, also serve /.well-known/oauth-protected-resource/* pointing at this resource URL")
		masterKeyB64   = flag.String("master-key-b64", os.Getenv("AUTHLET_MASTER_KEY"), "base64 32-byte AES-GCM master key (else random)")
	)
	flag.Parse()

	if *upstreamIssuer == "" {
		log.Fatal("--upstream-issuer required")
	}

	masterKey, err := loadMasterKey(*masterKeyB64)
	if err != nil {
		log.Fatalf("master key: %v", err)
	}

	store := memstore.New()
	mgr := jwt.NewManager(store.SigningKeys(), masterKey)
	if err := mgr.Bootstrap(context.Background()); err != nil {
		log.Fatalf("bootstrap: %v", err)
	}

	upstream, err := idp.NewOIDC(context.Background(), *upstreamIssuer, *upstreamClient, *upstreamSecret, *upstreamRedir, []string{"openid", "email", "profile"})
	if err != nil {
		log.Fatalf("upstream oidc: %v", err)
	}

	resolver := idp.UserResolverFunc(func(_ context.Context, c idp.Claims) (string, error) {
		if c.Email == "" {
			return "", errors.New("authletd: upstream claims missing email")
		}
		return c.Email, nil
	})

	server, err := as.New(as.Config{
		Issuer:       *issuer,
		PathPrefix:   "/oauth",
		Upstream:     upstream,
		UserResolver: resolver,
		Storage:      store,
		KeyManager:   mgr,
	})
	if err != nil {
		log.Fatalf("as.New: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/oauth/", http.StripPrefix("/oauth", server.Handler()))
	mux.HandleFunc("/.well-known/oauth-authorization-server", server.MetadataHandler)
	mux.HandleFunc("/.well-known/openid-configuration", server.OIDCMetadataHandler)
	mux.HandleFunc("/.well-known/jwks.json", server.JWKSHandler)
	if *prmResource != "" {
		mux.HandleFunc("/.well-known/oauth-protected-resource/", mcp.PRMHandler(mcp.PRM{
			Resource:               *prmResource,
			AuthorizationServers:   []string{*issuer},
			BearerMethodsSupported: []string{"header"},
			ScopesSupported:        []string{"mcp"},
		}))
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	go server.RunCleanup(ctx, time.Minute)

	srv := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		log.Printf("authletd listening on %s (issuer %s)", *addr, *issuer)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("listen: %v", err)
		}
	}()
	<-ctx.Done()
	log.Println("authletd shutting down")
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelShutdown()
	_ = srv.Shutdown(shutdownCtx)
}

func loadMasterKey(b64 string) ([]byte, error) {
	if b64 != "" {
		return base64.StdEncoding.DecodeString(b64)
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	log.Printf("authletd: generated ephemeral master key (set AUTHLET_MASTER_KEY for persistence)")
	return k, nil
}
