package as

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// pendingAuth holds the in-flight authorize request between the user-agent
// redirect upstream and the IdP callback returning.
type pendingAuth struct {
	ClientID            string
	RedirectURI         string
	Scope               string
	Resource            string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time
}

// stateStore is the in-memory map of pending authorize requests keyed by a
// server-generated state key. Entries are consumed (delete-on-read) at the
// IdP callback and garbage-collected by RunCleanup.
type stateStore struct {
	mu sync.Mutex
	m  map[string]pendingAuth
}

func newStateStore() *stateStore { return &stateStore{m: map[string]pendingAuth{}} }

// Put stores a pendingAuth keyed by the given state key.
func (s *stateStore) Put(key string, p pendingAuth) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[key] = p
}

// Consume returns and removes the pendingAuth for the given key. Returns
// ok=false if the key is unknown or the entry has expired.
func (s *stateStore) Consume(key string) (pendingAuth, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.m[key]
	if !ok {
		return pendingAuth{}, false
	}
	delete(s.m, key)
	if time.Now().After(p.ExpiresAt) {
		return pendingAuth{}, false
	}
	return p, true
}

// GC removes any entries whose ExpiresAt is before the given time.
func (s *stateStore) GC(before time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, p := range s.m {
		if p.ExpiresAt.Before(before) {
			delete(s.m, k)
		}
	}
}

// newStateKey returns a random base64url-encoded key suitable for stashing
// a pendingAuth.
func newStateKey() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
