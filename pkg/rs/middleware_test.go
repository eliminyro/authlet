package rs

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/eliminyro/authlet/pkg/jwt"
	"github.com/eliminyro/authlet/pkg/storage/memstore"
)

func newJWKSBackedClient(t *testing.T) (*JWKSClient, *jwt.Manager) {
	t.Helper()
	mk := make([]byte, 32)
	_, _ = rand.Read(mk)
	store := memstore.New()
	mgr := jwt.NewManager(store.SigningKeys(), mk)
	_ = mgr.Bootstrap(context.Background())
	jwks, _ := mgr.PublishJWKS(context.Background())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	t.Cleanup(srv.Close)
	return NewJWKSClient(srv.URL, time.Minute), mgr
}

func mintTestToken(t *testing.T, mgr *jwt.Manager, iss, aud string, exp time.Duration) string {
	t.Helper()
	priv, kid, err := mgr.Signer(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	tok, err := jwt.Sign(jwt.Claims{
		Issuer: iss, Subject: "u1", Audience: aud, ClientID: "c",
		IssuedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(exp).Unix(),
	}, kid, priv)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestMiddleware_AcceptsValidToken(t *testing.T) {
	c, mgr := newJWKSBackedClient(t)
	tok := mintTestToken(t, mgr, "https://issuer", "https://rs/api", time.Hour)
	mw := Middleware(Config{ExpectedIssuer: "https://issuer", ExpectedAudience: "https://rs/api", JWKS: c})
	called := false
	h := mw(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		called = true
		if _, ok := FromContext(r.Context()); !ok {
			t.Fatal("claims missing")
		}
	}))
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	h.ServeHTTP(httptest.NewRecorder(), req)
	if !called {
		t.Fatal("next handler not called")
	}
}

func TestMiddleware_RejectsNoBearer(t *testing.T) {
	c, _ := newJWKSBackedClient(t)
	mw := Middleware(Config{JWKS: c, ResourceMetadata: "https://rs/.well-known/oauth-protected-resource/api"})
	w := httptest.NewRecorder()
	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", w.Code)
	}
	if want := `resource_metadata="https://rs/.well-known/oauth-protected-resource/api"`; !contains(w.Header().Get("WWW-Authenticate"), want) {
		t.Fatalf("WWW-Authenticate missing PRM: %q", w.Header().Get("WWW-Authenticate"))
	}
}

func TestMiddleware_RejectsWrongAudience(t *testing.T) {
	c, mgr := newJWKSBackedClient(t)
	tok := mintTestToken(t, mgr, "https://issuer", "https://OTHER/api", time.Hour)
	mw := Middleware(Config{ExpectedIssuer: "https://issuer", ExpectedAudience: "https://rs/api", JWKS: c})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", w.Code)
	}
}

func TestMiddleware_RejectsExpired(t *testing.T) {
	c, mgr := newJWKSBackedClient(t)
	tok := mintTestToken(t, mgr, "https://issuer", "https://rs/api", -time.Minute)
	mw := Middleware(Config{ExpectedIssuer: "https://issuer", ExpectedAudience: "https://rs/api", JWKS: c})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", w.Code)
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
