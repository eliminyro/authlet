package rs

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
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

// TestJWKSClient_RejectsEmptyParsedCache asserts that a refresh which
// parses zero usable keys does NOT wipe the existing cache. Without
// this guard, an upstream JWKS endpoint serving malformed JSON or only
// non-RS256 keys would silently DoS the resource server.
func TestJWKSClient_RejectsEmptyParsedCache(t *testing.T) {
	priv, _ := jwt.GenerateRSA()

	// Two-phase server: first request returns the valid key (warms the
	// cache + sets ETag); subsequent requests return zero usable keys.
	var phase int
	mux := http.NewServeMux()
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if phase == 0 {
			w.Header().Set("ETag", "\"v1\"")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"keys": []map[string]any{{
					"kty": "RSA", "alg": "RS256", "kid": "k1",
					"n": base64.RawURLEncoding.EncodeToString(priv.N.Bytes()),
					"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.E)).Bytes()),
				}},
			})
			phase = 1
			return
		}
		// Subsequent: all keys are non-RS256, so newCache parses empty.
		w.Header().Set("ETag", "\"v2\"")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA", "alg": "PS256", "kid": "bogus",
				"n": base64.RawURLEncoding.EncodeToString(priv.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.E)).Bytes()),
			}},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// 1 ns TTL ensures every Key call sees a stale cache; disabling the
	// negative-refresh backoff (minRefreshInterval=0) lets the second call
	// actually re-fetch so we exercise the 0-usable-keys guard.
	c := NewJWKSClient(srv.URL+"/jwks", time.Nanosecond)
	c.minRefreshInterval = 0
	if _, err := c.Key(context.Background(), "k1"); err != nil {
		t.Fatalf("expected cache to warm with valid key, got %v", err)
	}
	// Second call: refresh returns 0-usable-keys document. The guard
	// MUST return an error from refresh and NOT replace the cache.
	if _, err := c.Key(context.Background(), "k1"); err == nil {
		t.Fatal("expected refresh error when upstream returned 0 usable keys")
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

// TestJWKSClient_UnknownKidNoFetchWhenFresh is the core DoS guard: while the
// cache is still fresh, a flood of unknown kids must NOT trigger any upstream
// refresh. Previously every unknown-kid request forced a serialized fetch,
// letting an attacker stall all token validation with random kids.
func TestJWKSClient_UnknownKidNoFetchWhenFresh(t *testing.T) {
	priv, _ := jwt.GenerateRSA()
	hits := 0
	srv := startJWKSServer(t, &priv.PublicKey, "k1", &hits)
	defer srv.Close()
	c := NewJWKSClient(srv.URL+"/jwks", time.Minute)

	// Warm the cache (1 fetch).
	if _, err := c.Key(context.Background(), "k1"); err != nil {
		t.Fatal(err)
	}
	if hits != 1 {
		t.Fatalf("expected 1 fetch after warm, got %d", hits)
	}
	// Burst of unknown kids against a fresh cache: zero additional fetches.
	for i := 0; i < 100; i++ {
		if _, err := c.Key(context.Background(), "unknown"); err == nil {
			t.Fatal("expected ErrNoKey for unknown kid")
		}
	}
	if hits != 1 {
		t.Fatalf("unknown-kid flood on fresh cache triggered %d fetches, want 1", hits)
	}
}

// TestJWKSClient_UnknownKidBurstOneFetchPerInterval asserts that once the
// cache is stale, a burst of unknown kids triggers at most one upstream fetch
// per refresh (the successful refresh re-marks the cache fresh, so the rest of
// the burst is served without fetching).
func TestJWKSClient_UnknownKidBurstOneFetchPerInterval(t *testing.T) {
	priv, _ := jwt.GenerateRSA()
	hits := 0
	srv := startJWKSServer(t, &priv.PublicKey, "k1", &hits)
	defer srv.Close()
	c := NewJWKSClient(srv.URL+"/jwks", time.Minute)

	now := time.Unix(1_000_000, 0)
	c.now = func() time.Time { return now }

	if _, err := c.Key(context.Background(), "k1"); err != nil {
		t.Fatal(err)
	}
	if hits != 1 {
		t.Fatalf("expected 1 fetch after warm, got %d", hits)
	}
	// Advance past both the cache TTL and the min refresh interval.
	now = now.Add(2 * time.Minute)
	for i := 0; i < 100; i++ {
		_, _ = c.Key(context.Background(), "unknown")
	}
	if hits != 2 {
		t.Fatalf("stale unknown-kid burst triggered %d fetches, want 2 (warm + one refresh)", hits)
	}
}

// TestJWKSClient_NewKidAfterExpiryRefreshes proves legitimate key rotation
// still works: a genuinely new kid, requested after the cache has expired,
// triggers exactly one refresh that picks it up.
func TestJWKSClient_NewKidAfterExpiryRefreshes(t *testing.T) {
	priv, _ := jwt.GenerateRSA()

	var mu sync.Mutex
	newKid := false
	mux := http.NewServeMux()
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		kid := "k1"
		if newKid {
			kid = "k2"
		}
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
				"n": base64.RawURLEncoding.EncodeToString(priv.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.E)).Bytes()),
			}},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewJWKSClient(srv.URL+"/jwks", time.Minute)
	now := time.Unix(2_000_000, 0)
	c.now = func() time.Time { return now }

	if _, err := c.Key(context.Background(), "k1"); err != nil {
		t.Fatal(err)
	}
	// Rotation happens upstream; cache expires.
	mu.Lock()
	newKid = true
	mu.Unlock()
	now = now.Add(2 * time.Minute)

	pk, err := c.Key(context.Background(), "k2")
	if err != nil {
		t.Fatalf("new kid after expiry not picked up: %v", err)
	}
	if !pk.Equal(&priv.PublicKey) {
		t.Fatal("wrong key returned for rotated kid")
	}
}

// TestJWKSClient_ConcurrentUnknownKidNoStampede fires many concurrent
// unknown-kid requests at a cold client; they must collapse into a single
// upstream fetch rather than each triggering one.
func TestJWKSClient_ConcurrentUnknownKidNoStampede(t *testing.T) {
	priv, _ := jwt.GenerateRSA()
	hits := 0
	srv := startJWKSServer(t, &priv.PublicKey, "k1", &hits)
	defer srv.Close()
	c := NewJWKSClient(srv.URL+"/jwks", time.Minute)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = c.Key(context.Background(), "unknown")
		}()
	}
	wg.Wait()
	if hits != 1 {
		t.Fatalf("concurrent unknown-kid stampede triggered %d fetches, want 1", hits)
	}
}
