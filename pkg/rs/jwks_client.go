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

// JWKSClient fetches and caches a remote JWKS, honouring ETag-based
// conditional refresh so unchanged documents incur no redundant decoding.
type JWKSClient struct {
	url      string
	cacheTTL time.Duration
	http     *http.Client

	mu        sync.Mutex
	cache     map[string]*rsa.PublicKey
	expiresAt time.Time
	etag      string
}

// NewJWKSClient builds a client that fetches the JWKS document at jwksURL
// and caches parsed keys for ttl. A ttl of 0 selects the default of one hour.
func NewJWKSClient(jwksURL string, ttl time.Duration) *JWKSClient {
	if ttl == 0 {
		ttl = time.Hour
	}
	return &JWKSClient{
		url:      jwksURL,
		cacheTTL: ttl,
		http:     &http.Client{Timeout: 10 * time.Second},
		cache:    map[string]*rsa.PublicKey{},
	}
}

// Key returns the RSA public key for kid, refreshing the cache from the
// upstream JWKS endpoint if the cached copy is stale or missing the kid.
func (c *JWKSClient) Key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	c.mu.Lock()
	cached := c.cache[kid]
	fresh := time.Now().Before(c.expiresAt)
	c.mu.Unlock()
	if cached != nil && fresh {
		return cached, nil
	}
	if err := c.refresh(ctx); err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
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

// refresh fetches the JWKS document from the upstream URL. It sends
// If-None-Match when an ETag is known so unchanged documents short-circuit
// to a 304 and only the cache expiry is bumped.
func (c *JWKSClient) refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return err
	}
	c.mu.Lock()
	if c.etag != "" {
		req.Header.Set("If-None-Match", c.etag)
	}
	c.mu.Unlock()
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("jwks fetch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotModified {
		c.mu.Lock()
		c.expiresAt = time.Now().Add(c.cacheTTL)
		c.mu.Unlock()
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
	c.mu.Lock()
	c.cache = newCache
	c.expiresAt = time.Now().Add(c.cacheTTL)
	c.etag = resp.Header.Get("ETag")
	c.mu.Unlock()
	return nil
}
