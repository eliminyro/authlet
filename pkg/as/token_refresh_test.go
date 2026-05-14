package as

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eliminyro/authlet/pkg/storage"
)

func seedRefresh(t *testing.T, a *AS, clientID, resource string) string {
	t.Helper()
	plain, _ := randomID(32)
	_ = a.cfg.Storage.RefreshTokens().Save(context.Background(), storage.RefreshToken{
		TokenHash: hashCode(plain),
		FamilyID:  "fam1",
		ClientID:  clientID,
		UserID:    "user1",
		Resource:  resource,
		Scope:     "mcp",
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
	})
	return plain
}

func refreshRequest(plain, clientID string) *http.Request {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", plain)
	form.Set("client_id", clientID)
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func TestToken_RefreshHappyPath(t *testing.T) {
	a := newTestAS(t)
	cid := registerTestClient(t, a, "https://claude/cb")
	plain := seedRefresh(t, a, cid, "https://rs/api")
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, refreshRequest(plain, cid))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body=%s", w.Code, w.Body.String())
	}
	var tr tokenResponse
	_ = json.Unmarshal(w.Body.Bytes(), &tr)
	if tr.RefreshToken == "" || tr.RefreshToken == plain {
		t.Fatalf("expected rotated refresh, got %q", tr.RefreshToken)
	}
}

func TestToken_RefreshReuseRevokesFamily(t *testing.T) {
	a := newTestAS(t)
	cid := registerTestClient(t, a, "https://claude/cb")
	plain := seedRefresh(t, a, cid, "https://rs/api")

	// First refresh — succeeds.
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, refreshRequest(plain, cid))
	if w.Code != http.StatusOK {
		t.Fatalf("first refresh status %d", w.Code)
	}
	// Replay the burned token — must fail and revoke family.
	w = httptest.NewRecorder()
	a.Handler().ServeHTTP(w, refreshRequest(plain, cid))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected reuse to be rejected, got %d", w.Code)
	}
	revoked, _ := a.cfg.Storage.RefreshTokens().IsFamilyRevoked(context.Background(), "fam1")
	if !revoked {
		t.Fatal("family should be revoked after reuse")
	}
}

// TestToken_RefreshRotationIsAtomic fires N concurrent rotations against
// the same refresh token and asserts that at most one succeeds. Combined
// with -race, this guards the rotation TOCTOU race fixed in F1.
func TestToken_RefreshRotationIsAtomic(t *testing.T) {
	a := newTestAS(t)
	cid := registerTestClient(t, a, "https://claude/cb")
	plain := seedRefresh(t, a, cid, "https://rs/api")

	const N = 16
	var wg sync.WaitGroup
	codes := make([]int, N)
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func(idx int) {
			defer wg.Done()
			w := httptest.NewRecorder()
			a.Handler().ServeHTTP(w, refreshRequest(plain, cid))
			codes[idx] = w.Code
		}(i)
	}
	wg.Wait()
	successes := 0
	for _, c := range codes {
		if c == http.StatusOK {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("expected exactly 1 successful rotation under concurrency, got %d (codes=%v)", successes, codes)
	}
	// Family must be revoked because losing goroutines treated their
	// MarkUsed conflict as reuse.
	revoked, _ := a.cfg.Storage.RefreshTokens().IsFamilyRevoked(context.Background(), "fam1")
	if !revoked {
		t.Fatal("expected family revoked after concurrent rotation")
	}
}

func TestToken_RefreshClientMismatch(t *testing.T) {
	a := newTestAS(t)
	cid := registerTestClient(t, a, "https://claude/cb")
	other := registerTestClient(t, a, "https://other/cb")
	plain := seedRefresh(t, a, cid, "https://rs/api")
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, refreshRequest(plain, other))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status %d", w.Code)
	}
}

// failingSaveRefreshStore wraps a RefreshTokenStore and makes the next
// Save call return an injected error. All other methods delegate.
type failingSaveRefreshStore struct {
	storage.RefreshTokenStore
	failNext bool
}

type errInjectedSentinel string

func (e errInjectedSentinel) Error() string { return string(e) }

var errInjected = errInjectedSentinel("injected save failure")

func (f *failingSaveRefreshStore) Save(ctx context.Context, rt storage.RefreshToken) error {
	if f.failNext {
		f.failNext = false
		return errInjected
	}
	return f.RefreshTokenStore.Save(ctx, rt)
}

// stubStorage wraps a real storage but swaps in the failing refresh
// store. Other accessors delegate.
type stubStorage struct {
	inner   storage.Storage
	refresh *failingSaveRefreshStore
}

func (s *stubStorage) Clients() storage.ClientStore             { return s.inner.Clients() }
func (s *stubStorage) Codes() storage.CodeStore                 { return s.inner.Codes() }
func (s *stubStorage) RefreshTokens() storage.RefreshTokenStore { return s.refresh }
func (s *stubStorage) SigningKeys() storage.SigningKeyStore     { return s.inner.SigningKeys() }

// TestToken_RefreshRollbackOnSaveFailure asserts that when the
// RefreshTokens.Save call during rotation fails, the OLD refresh token
// remains usable — the user is NOT bricked out of their session.
//
// Regression guard for the F1-era ordering bug: prior code called
// MarkUsed BEFORE Save, so a transient Save failure left the old token
// marked replaced (re-presenting it then revoked the family). The fix
// is to Save first; on failure the old token is still active.
func TestToken_RefreshRollbackOnSaveFailure(t *testing.T) {
	a := newTestAS(t)
	cid := registerTestClient(t, a, "https://claude/cb")
	plain := seedRefresh(t, a, cid, "https://rs/api")
	// Swap in a storage whose RefreshTokens.Save fails the next time it
	// is called. Seed already used the underlying memstore directly.
	inner := a.cfg.Storage
	failing := &failingSaveRefreshStore{RefreshTokenStore: inner.RefreshTokens(), failNext: true}
	a.cfg.Storage = &stubStorage{inner: inner, refresh: failing}

	// First refresh: Save() fails, rotation aborts at step 4. Server
	// must return 500 and NOT advance to MarkUsed.
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, refreshRequest(plain, cid))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 from failed Save, got %d body=%s", w.Code, w.Body.String())
	}

	// Old token must still be usable. With Save now succeeding, retry
	// must return 200 and rotate normally.
	w = httptest.NewRecorder()
	a.Handler().ServeHTTP(w, refreshRequest(plain, cid))
	if w.Code != http.StatusOK {
		t.Fatalf("expected old token still valid after rolled-back rotation, got %d body=%s", w.Code, w.Body.String())
	}
	revoked, _ := a.cfg.Storage.RefreshTokens().IsFamilyRevoked(context.Background(), "fam1")
	if revoked {
		t.Fatal("family should not be revoked after a transient Save failure")
	}
}
