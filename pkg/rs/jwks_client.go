// Package rs provides bearer-token middleware for resource servers
// protected by an authlet AS.
package rs

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// ErrNoKey is returned by JWKSClient.Key when the requested kid is not
// present in the freshly fetched JWKS document.
var ErrNoKey = errors.New("rs: no matching JWKS key")

// DefaultMinRefreshInterval is the minimum spacing between upstream JWKS
// fetches once the cache is stale. It bounds how often a stale cache (e.g.
// during an upstream outage, or a flood of unknown kids arriving after
// expiry) can trigger a serialized upstream refresh.
const DefaultMinRefreshInterval = time.Minute

// JWKSClient fetches and caches a remote JWKS, honouring ETag-based
// conditional refresh so unchanged documents incur no redundant decoding.
type JWKSClient struct {
	url                string
	cacheTTL           time.Duration
	minRefreshInterval time.Duration
	http               *http.Client

	mu          sync.Mutex
	cache       map[string]*rsa.PublicKey
	expiresAt   time.Time
	lastRefresh time.Time
	etag        string
	now         func() time.Time
}

// NewJWKSClient builds a client that fetches the JWKS document at jwksURL
// and caches parsed keys for ttl. A ttl of 0 selects the default of one hour.
func NewJWKSClient(jwksURL string, ttl time.Duration) *JWKSClient {
	if ttl == 0 {
		ttl = time.Hour
	}
	return &JWKSClient{
		url:                jwksURL,
		cacheTTL:           ttl,
		minRefreshInterval: DefaultMinRefreshInterval,
		http:               &http.Client{Timeout: 10 * time.Second},
		cache:              map[string]*rsa.PublicKey{},
		now:                time.Now,
	}
}

// Key returns the RSA public key for kid.
//
// The cache is refreshed from the upstream JWKS endpoint ONLY when it is
// actually stale (past expiresAt). A cache miss while the cache is still
// fresh returns ErrNoKey without any upstream fetch — otherwise a flood of
// bearer tokens carrying random unknown kids would force a serialized
// refresh on every request and stall all token validation (DoS).
//
// When the cache is stale, refreshes are additionally rate-limited to at
// most one per minRefreshInterval so repeated misses during an upstream
// outage (or a stale-window flood) cannot trigger unbounded serialized
// fetches. Within that backoff window the (stale) cache is served as-is.
//
// The lock is held for the entire refresh so concurrent callers serialise
// rather than producing a thundering herd of upstream JWKS fetches.
func (c *JWKSClient) Key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()

	// Fast path: fresh cache hit.
	if pk, ok := c.cache[kid]; ok && now.Before(c.expiresAt) {
		return pk, nil
	}
	// Cache is still fresh but lacks this kid: the kid is genuinely unknown.
	// Do NOT fetch — an unknown kid must never trigger an upstream refresh
	// while the cache is valid.
	if now.Before(c.expiresAt) {
		return nil, ErrNoKey
	}
	// Cache is stale. Back off if we refreshed within minRefreshInterval,
	// serving whatever the stale cache still holds. minRefreshInterval == 0
	// disables the backoff (fetch on every stale miss).
	if c.minRefreshInterval > 0 && !c.lastRefresh.IsZero() &&
		now.Sub(c.lastRefresh) < c.minRefreshInterval {
		if pk, ok := c.cache[kid]; ok {
			return pk, nil
		}
		return nil, ErrNoKey
	}
	c.lastRefresh = now
	if err := c.refreshLocked(ctx); err != nil {
		return nil, err
	}
	pk, ok := c.cache[kid]
	if !ok {
		return nil, ErrNoKey
	}
	return pk, nil
}

type jwksDoc struct {
	Keys []struct {
		Kid string `json:"kid"`
		Kty string `json:"kty"`
		Alg string `json:"alg"`
		N   string `json:"n"`
		E   string `json:"e"`
	} `json:"keys"`
}

// refreshLocked fetches the JWKS document from the upstream URL. The
// caller MUST hold c.mu. It sends If-None-Match when an ETag is known so
// unchanged documents short-circuit to a 304 and only the cache expiry is
// bumped.
func (c *JWKSClient) refreshLocked(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return err
	}
	if c.etag != "" {
		req.Header.Set("If-None-Match", c.etag)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("jwks fetch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotModified {
		c.expiresAt = c.now().Add(c.cacheTTL)
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks status %d", resp.StatusCode)
	}
	var doc jwksDoc
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return err
	}
	newCache := map[string]*rsa.PublicKey{}
	for _, k := range doc.Keys {
		if k.Kty != "RSA" {
			continue
		}
		// Per RFC 7517 §4.4, alg is optional. When present it MUST be
		// RS256 for our purposes; reject anything else to avoid
		// algorithm confusion.
		if k.Alg != "" && k.Alg != "RS256" {
			continue
		}
		nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			continue
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			continue
		}
		eBI := new(big.Int).SetBytes(eBytes)
		newCache[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: int(eBI.Int64())}
	}
	// Guard against a parsed-zero-keys response replacing a healthy
	// cache. If the upstream JWKS endpoint serves malformed JSON or
	// only non-RS256 keys we'd otherwise wipe the cache and trigger a
	// silent DoS where every Bearer token returns 401 ErrNoKey. Keep
	// the existing cache and return an error instead so the caller can
	// log + retry. The cache TTL stays untouched so the next call
	// refreshes again.
	if len(newCache) == 0 {
		return fmt.Errorf("jwks: parsed 0 usable keys (response had %d total)", len(doc.Keys))
	}
	c.cache = newCache
	c.expiresAt = c.now().Add(c.cacheTTL)
	c.etag = resp.Header.Get("ETag")
	return nil
}
