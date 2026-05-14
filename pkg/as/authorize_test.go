package as

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/eliminyro/authlet/pkg/storage"
)

func registerTestClient(t *testing.T, a *AS, redirect string) string {
	t.Helper()
	id, _ := randomID(8)
	_ = a.cfg.Storage.Clients().Create(context.Background(), storage.Client{
		ClientID:     id,
		RedirectURIs: []string{redirect},
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(24 * time.Hour),
	})
	return id
}

func TestAuthorize_RejectsNonCodeResponseType(t *testing.T) {
	a := newTestAS(t)
	req := httptest.NewRequest(http.MethodGet, "/authorize?response_type=token&client_id=x", nil)
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status %d", w.Code)
	}
}

func TestAuthorize_RequiresPKCES256(t *testing.T) {
	a := newTestAS(t)
	cid := registerTestClient(t, a, "https://claude/cb")
	url := "/authorize?response_type=code&client_id=" + cid + "&redirect_uri=https://claude/cb&resource=https://rs/api"
	req := httptest.NewRequest(http.MethodGet, url, nil)
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 (missing PKCE), got %d", w.Code)
	}
}

func TestAuthorize_RequiresResource(t *testing.T) {
	a := newTestAS(t)
	cid := registerTestClient(t, a, "https://claude/cb")
	url := "/authorize?response_type=code&client_id=" + cid + "&redirect_uri=https://claude/cb&code_challenge=abc&code_challenge_method=S256"
	req := httptest.NewRequest(http.MethodGet, url, nil)
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 (missing resource), got %d", w.Code)
	}
}

func TestAuthorize_RejectsUnknownRedirect(t *testing.T) {
	a := newTestAS(t)
	cid := registerTestClient(t, a, "https://claude/cb")
	url := "/authorize?response_type=code&client_id=" + cid + "&redirect_uri=https://evil/cb&code_challenge=abc&code_challenge_method=S256&resource=https://rs/api"
	req := httptest.NewRequest(http.MethodGet, url, nil)
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}
