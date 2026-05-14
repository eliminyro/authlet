package idp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
)

// fakeOIDC starts an httptest server that pretends to be an OIDC issuer
// such as Google.
type fakeOIDC struct {
	server   *httptest.Server
	key      *rsa.PrivateKey
	kid      string
	clientID string
}

func newFakeOIDC(t *testing.T, clientID string) *fakeOIDC {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	f := &fakeOIDC{key: k, kid: "fk1", clientID: clientID}
	mux := http.NewServeMux()
	var issuer string
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                issuer,
			"authorization_endpoint":                issuer + "/authorize",
			"token_endpoint":                        issuer + "/token",
			"jwks_uri":                              issuer + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		n := base64.RawURLEncoding.EncodeToString(k.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes())
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": f.kid, "n": n, "e": e}},
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		id := makeIDToken(t, k, f.kid, issuer, clientID, "google-sub-123", "alice@example.com")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "fake-at",
			"id_token":     id,
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	})
	f.server = httptest.NewServer(mux)
	issuer = f.server.URL
	return f
}

func makeIDToken(t *testing.T, k *rsa.PrivateKey, kid, iss, aud, sub, email string) string {
	t.Helper()
	tok := jwtv5.NewWithClaims(jwtv5.SigningMethodRS256, jwtv5.MapClaims{
		"iss":            iss,
		"sub":            sub,
		"aud":            aud,
		"email":          email,
		"email_verified": true,
		"name":           "Alice",
		"iat":            time.Now().Unix(),
		"exp":            time.Now().Add(time.Hour).Unix(),
	})
	tok.Header["kid"] = kid
	s, err := tok.SignedString(k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestOIDC_DiscoverAndExchange(t *testing.T) {
	f := newFakeOIDC(t, "client-A")
	defer f.server.Close()
	prov, err := NewOIDC(context.Background(), f.server.URL, "client-A", "secret", "https://app/callback", []string{"openid", "email"})
	if err != nil {
		t.Fatalf("NewOIDC: %v", err)
	}
	c, err := prov.Exchange(context.Background(), "any-code")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if c.Email != "alice@example.com" || c.Subject != "google-sub-123" {
		t.Fatalf("claims mismatch: %+v", c)
	}
	if prov.Issuer() != f.server.URL {
		t.Fatalf("Issuer mismatch: %q vs %q", prov.Issuer(), f.server.URL)
	}
}

func TestOIDC_AuthURLContainsState(t *testing.T) {
	f := newFakeOIDC(t, "client-A")
	defer f.server.Close()
	prov, err := NewOIDC(context.Background(), f.server.URL, "client-A", "secret", "https://app/cb", []string{"openid"})
	if err != nil {
		t.Fatalf("NewOIDC: %v", err)
	}
	u := prov.AuthURL("xyz")
	if !strings.Contains(u, "state=xyz") {
		t.Fatalf("state missing from %s", u)
	}
}
