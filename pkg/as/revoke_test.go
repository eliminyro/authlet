package as

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestRevoke_RevokesRefreshTokenFamily(t *testing.T) {
	a := newTestAS(t)
	cid := registerTestClient(t, a, "https://claude/cb")
	plain := seedRefresh(t, a, cid, "https://rs/api")

	form := url.Values{}
	form.Set("token", plain)
	form.Set("token_type_hint", "refresh_token")
	form.Set("client_id", cid)
	req := httptest.NewRequest(http.MethodPost, "/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	ok, _ := a.cfg.Storage.RefreshTokens().IsFamilyRevoked(context.Background(), "fam1")
	if !ok {
		t.Fatal("expected family revoked")
	}
}

func TestRevoke_EmptyTokenSilentSuccess(t *testing.T) {
	a := newTestAS(t)
	cid := registerTestClient(t, a, "https://claude/cb")
	form := url.Values{}
	form.Set("client_id", cid)
	req := httptest.NewRequest(http.MethodPost, "/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
}

// TestRevoke_RequiresClientAuth asserts unauthenticated requests are
// rejected with 401 + WWW-Authenticate per RFC 7009 §2.2.1.
func TestRevoke_RequiresClientAuth(t *testing.T) {
	a := newTestAS(t)
	req := httptest.NewRequest(http.MethodPost, "/revoke", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
	if got := w.Header().Get("WWW-Authenticate"); got == "" {
		t.Fatal("missing WWW-Authenticate header")
	}
}

// TestRevoke_OtherClientCannotRevoke asserts that a refresh token issued
// to client A cannot be revoked by authenticated client B. We return 200
// (no existence leak) but the family must remain valid.
func TestRevoke_OtherClientCannotRevoke(t *testing.T) {
	a := newTestAS(t)
	owner := registerTestClient(t, a, "https://claude/cb")
	intruder := registerTestClient(t, a, "https://evil/cb")
	plain := seedRefresh(t, a, owner, "https://rs/api")

	form := url.Values{}
	form.Set("token", plain)
	form.Set("client_id", intruder)
	req := httptest.NewRequest(http.MethodPost, "/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	revoked, _ := a.cfg.Storage.RefreshTokens().IsFamilyRevoked(context.Background(), "fam1")
	if revoked {
		t.Fatal("intruder should not be able to revoke another client's token")
	}
}
