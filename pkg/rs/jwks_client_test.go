package rs

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/eliminyro/authlet/pkg/jwt"
)

func startJWKSServer(t *testing.T, pk *rsa.PublicKey, kid string, hits *int) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		*hits++
		w.Header().Set("ETag", "\"v1\"")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
				"n": base64.RawURLEncoding.EncodeToString(pk.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pk.E)).Bytes()),
			}},
		})
	})
	return httptest.NewServer(mux)
}

func TestJWKSClient_FetchAndCache(t *testing.T) {
	priv, _ := jwt.GenerateRSA()
	hits := 0
	srv := startJWKSServer(t, &priv.PublicKey, "k1", &hits)
	defer srv.Close()
	c := NewJWKSClient(srv.URL+"/jwks", time.Minute)
	pk, err := c.Key(context.Background(), "k1")
	if err != nil {
		t.Fatal(err)
	}
	if !pk.Equal(&priv.PublicKey) {
		t.Fatal("wrong public key")
	}
	// Second hit should be served from cache.
	_, _ = c.Key(context.Background(), "k1")
	if hits != 1 {
		t.Fatalf("expected 1 upstream hit (cache), got %d", hits)
	}
}

func TestJWKSClient_UnknownKID(t *testing.T) {
	priv, _ := jwt.GenerateRSA()
	hits := 0
	srv := startJWKSServer(t, &priv.PublicKey, "k1", &hits)
	defer srv.Close()
	c := NewJWKSClient(srv.URL+"/jwks", time.Minute)
	if _, err := c.Key(context.Background(), "unknown"); err == nil {
		t.Fatal("expected error")
	}
}

// TestJWKSClient_SkipsNonRS256Alg verifies the client ignores JWKS entries
// whose alg is set but not RS256 (defense against algorithm confusion).
func TestJWKSClient_SkipsNonRS256Alg(t *testing.T) {
	priv, _ := jwt.GenerateRSA()
	mux := http.NewServeMux()
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA", "alg": "PS256", "kid": "ps",
				"n": base64.RawURLEncoding.EncodeToString(priv.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.E)).Bytes()),
			}},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := NewJWKSClient(srv.URL+"/jwks", time.Minute)
	if _, err := c.Key(context.Background(), "ps"); err == nil {
		t.Fatal("expected ErrNoKey: PS256 must be skipped")
	}
}
