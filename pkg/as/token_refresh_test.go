package as

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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
