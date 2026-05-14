package jwt

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/eliminyro/authlet/pkg/crypto"
	"github.com/eliminyro/authlet/pkg/storage"
)

// RotationInterval is how long an active signing key is used before the
// Manager rotates in a fresh one.
const RotationInterval = 30 * 24 * time.Hour

// OverlapWindow is how long a retired key remains queryable for signature
// verification after rotation, to allow in-flight tokens to validate.
const OverlapWindow = 24 * time.Hour

// ErrNoActiveKey is returned by Signer when storage has no active key.
var ErrNoActiveKey = errors.New("jwt: no active signing key")

// Manager owns the active RSA signing key, the rotation policy, and a
// kid->public key cache for verification. It wraps storage.SigningKeyStore
// and decrypts/encrypts private keys via pkg/crypto.
type Manager struct {
	store     storage.SigningKeyStore
	masterKey []byte

	mu     sync.RWMutex
	cache  map[string]*rsa.PublicKey
	signer *signerCache
	now    func() time.Time
}

type signerCache struct {
	kid string
	key *rsa.PrivateKey
}

// NewManager wires a Manager around a SigningKeyStore and the 32-byte master
// key used to encrypt private key material at rest.
func NewManager(store storage.SigningKeyStore, masterKey []byte) *Manager {
	return &Manager{
		store:     store,
		masterKey: masterKey,
		cache:     map[string]*rsa.PublicKey{},
		now:       time.Now,
	}
}

// Bootstrap ensures at least one active signing key exists. Idempotent:
// returns nil if storage already has an active signer.
func (m *Manager) Bootstrap(ctx context.Context) error {
	if _, err := m.store.GetSigner(ctx); err == nil {
		return nil
	} else if !errors.Is(err, storage.ErrNotFound) {
		return fmt.Errorf("getsigner: %w", err)
	}
	return m.insertNew(ctx, true)
}

// RotateIfDue creates a new active key if the current signer is older than
// RotationInterval, scheduling the old key to retire after OverlapWindow.
// No-op when the active signer is younger than RotationInterval.
func (m *Manager) RotateIfDue(ctx context.Context) error {
	signer, err := m.store.GetSigner(ctx)
	if err != nil {
		return fmt.Errorf("getsigner: %w", err)
	}
	if m.nowFn().Sub(signer.CreatedAt) < RotationInterval {
		return nil
	}
	if err := m.insertNew(ctx, true); err != nil {
		return err
	}
	// Invalidate caches so the new key becomes visible immediately.
	m.mu.Lock()
	m.signer = nil
	m.cache = map[string]*rsa.PublicKey{}
	m.mu.Unlock()
	return m.store.Retire(ctx, signer.ID, m.nowFn().Add(OverlapWindow))
}

func (m *Manager) insertNew(ctx context.Context, active bool) error {
	priv, err := GenerateRSA()
	if err != nil {
		return err
	}
	privPEM, err := MarshalPrivatePEM(priv)
	if err != nil {
		return err
	}
	enc, err := crypto.Encrypt(m.masterKey, privPEM)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}
	pubPEM, err := MarshalPublicPEM(&priv.PublicKey)
	if err != nil {
		return err
	}
	id := kidFromPub(&priv.PublicKey)
	return m.store.Insert(ctx, storage.SigningKey{
		ID:                  id,
		Algorithm:           "RS256",
		PublicPEM:           pubPEM,
		PrivatePEMEncrypted: enc,
		IsActive:            active,
		CreatedAt:           m.nowFn(),
	})
}

// Signer returns the active private key with its kid, decrypting from
// storage on first call and caching the result.
func (m *Manager) Signer(ctx context.Context) (*rsa.PrivateKey, string, error) {
	k, err := m.store.GetSigner(ctx)
	if err != nil {
		return nil, "", ErrNoActiveKey
	}
	m.mu.RLock()
	if m.signer != nil && m.signer.kid == k.ID {
		defer m.mu.RUnlock()
		return m.signer.key, m.signer.kid, nil
	}
	m.mu.RUnlock()

	privPEM, err := crypto.Decrypt(m.masterKey, k.PrivatePEMEncrypted)
	if err != nil {
		return nil, "", fmt.Errorf("decrypt: %w", err)
	}
	priv, err := ParsePrivatePEM(privPEM)
	if err != nil {
		return nil, "", err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	// Re-check under the write lock: another goroutine may have populated
	// the cache for the same kid while we were decrypting.
	if m.signer != nil && m.signer.kid == k.ID {
		return m.signer.key, m.signer.kid, nil
	}
	m.signer = &signerCache{kid: k.ID, key: priv}
	return priv, k.ID, nil
}

// PublicKeyFunc returns a resolver suitable for Verify(). The resolver
// honours the Manager's clock so retired keys past the overlap window are
// not returned, even if the underlying store has not yet pruned them.
func (m *Manager) PublicKeyFunc(ctx context.Context) PublicKeyFunc {
	return func(kid string) (*rsa.PublicKey, error) {
		m.mu.RLock()
		if pk, ok := m.cache[kid]; ok {
			m.mu.RUnlock()
			return pk, nil
		}
		m.mu.RUnlock()
		// Miss: reload from store, applying manager-clock filtering.
		ks, err := m.activeKeys(ctx)
		if err != nil {
			return nil, err
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		// Re-check under the write lock — another goroutine may have
		// already refreshed the cache for this kid.
		if pk, ok := m.cache[kid]; ok {
			return pk, nil
		}
		// Merge fresh entries into the existing cache rather than
		// wiping it; concurrent verifiers may still hold pointers we
		// want to keep serving from cache.
		for _, k := range ks {
			pub, perr := ParsePublicPEM(k.PublicPEM)
			if perr != nil {
				return nil, perr
			}
			m.cache[k.ID] = pub
		}
		pk, ok := m.cache[kid]
		if !ok {
			return nil, ErrUnknownKID
		}
		return pk, nil
	}
}

// PublishJWKS returns a JWKS of every key currently considered active by
// the Manager, i.e. unretired or still within the overlap window.
func (m *Manager) PublishJWKS(ctx context.Context) (JWKS, error) {
	ks, err := m.activeKeys(ctx)
	if err != nil {
		return JWKS{}, err
	}
	out := map[string]*rsa.PublicKey{}
	for _, k := range ks {
		pub, err := ParsePublicPEM(k.PublicPEM)
		if err != nil {
			return JWKS{}, err
		}
		out[k.ID] = pub
	}
	return PublishJWKS(out), nil
}

// activeKeys returns store.ListActive results filtered against the
// Manager's own clock. This is what isolates rotation tests from real time
// and what allows downstream drivers to use a coarser retirement filter.
func (m *Manager) activeKeys(ctx context.Context) ([]storage.SigningKey, error) {
	ks, err := m.store.ListActive(ctx)
	if err != nil {
		return nil, err
	}
	now := m.nowFn()
	out := ks[:0:0]
	for _, k := range ks {
		if k.RetiresAt != nil && !k.RetiresAt.After(now) {
			continue
		}
		out = append(out, k)
	}
	return out, nil
}

// SetNow swaps the Manager's clock. Intended for tests. Safe for use from
// any goroutine; locks the manager's internal mutex.
func (m *Manager) SetNow(f func() time.Time) {
	m.mu.Lock()
	m.now = f
	m.mu.Unlock()
}

// nowFn returns the current time using the manager's configured clock,
// holding the manager's RLock so a concurrent SetNow is serialised.
func (m *Manager) nowFn() time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.now()
}

// kidFromPub derives a stable kid from the public key by hashing its PKIX
// PEM encoding and taking the first 12 bytes as hex.
func kidFromPub(pk *rsa.PublicKey) string {
	der, _ := MarshalPublicPEM(pk)
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:12])
}
