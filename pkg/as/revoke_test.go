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
	req := httptest.NewRequest(http.MethodPost, "/revoke", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
}
