package as

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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
	u := "/authorize?response_type=code&client_id=" + cid + "&redirect_uri=https://claude/cb&resource=https://rs/api&state=xyz"
	req := httptest.NewRequest(http.MethodGet, u, nil)
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		t.Fatalf("expected 302 (PKCE error redirect), got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	parsed, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("bad redirect URL: %v", err)
	}
	if parsed.Host != "claude" {
		t.Fatalf("redirect should go to client, got %q", loc)
	}
	if parsed.Query().Get("error") != "invalid_request" {
		t.Fatalf("missing/wrong error in redirect: %q", loc)
	}
	if parsed.Query().Get("state") != "xyz" {
		t.Fatalf("state not preserved: %q", loc)
	}
}

func TestAuthorize_RequiresResource(t *testing.T) {
	a := newTestAS(t)
	cid := registerTestClient(t, a, "https://claude/cb")
	u := "/authorize?response_type=code&client_id=" + cid + "&redirect_uri=https://claude/cb&code_challenge=abc&code_challenge_method=S256&state=xyz"
	req := httptest.NewRequest(http.MethodGet, u, nil)
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		t.Fatalf("expected 302 (resource error redirect), got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	parsed, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("bad redirect URL: %v", err)
	}
	if parsed.Query().Get("error") != "invalid_target" {
		t.Fatalf("missing/wrong error in redirect: %q", loc)
	}
	if parsed.Query().Get("state") != "xyz" {
		t.Fatalf("state not preserved: %q", loc)
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

// TestAuthorize_RejectsRelativeResource asserts that a non-absolute
// resource indicator (e.g. "/api") is rejected with invalid_target per
// RFC 8707 §2.
func TestAuthorize_RejectsRelativeResource(t *testing.T) {
	a := newTestAS(t)
	cid := registerTestClient(t, a, "https://claude/cb")
	u := "/authorize?response_type=code&client_id=" + cid + "&redirect_uri=https://claude/cb&code_challenge=abc&code_challenge_method=S256&resource=%2Frelative"
	req := httptest.NewRequest(http.MethodGet, u, nil)
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		t.Fatalf("expected 302 error redirect, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "error=invalid_target") {
		t.Fatalf("expected invalid_target in redirect, got %q", loc)
	}
}

// TestAuthorize_RejectsHTTPResourceForNonLocalhost asserts that an
// http:// resource pointing at a non-loopback host is rejected.
func TestAuthorize_RejectsHTTPResourceForNonLocalhost(t *testing.T) {
	a := newTestAS(t)
	cid := registerTestClient(t, a, "https://claude/cb")
	u := "/authorize?response_type=code&client_id=" + cid + "&redirect_uri=https://claude/cb&code_challenge=abc&code_challenge_method=S256&resource=http%3A%2F%2Frs.example%2Fapi"
	req := httptest.NewRequest(http.MethodGet, u, nil)
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		t.Fatalf("expected 302 error redirect, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "error=invalid_target") {
		t.Fatalf("expected invalid_target in redirect, got %q", loc)
	}
}

// TestAuthorize_AcceptsHTTPLocalhost asserts that http:// resources
// pointing at loopback hosts are accepted (for dev convenience).
func TestAuthorize_AcceptsHTTPLocalhost(t *testing.T) {
	a := newTestAS(t)
	cid := registerTestClient(t, a, "https://claude/cb")
	for _, host := range []string{"http://localhost:8080/api", "http://127.0.0.1:8080/api"} {
		u := "/authorize?response_type=code&client_id=" + cid + "&redirect_uri=https://claude/cb&code_challenge=abc&code_challenge_method=S256&resource=" + url.QueryEscape(host)
		req := httptest.NewRequest(http.MethodGet, u, nil)
		w := httptest.NewRecorder()
		a.Handler().ServeHTTP(w, req)
		// Should pass resource validation and 302 to the upstream IdP.
		if w.Code != http.StatusFound {
			t.Fatalf("expected 302 (upstream redirect) for %q, got %d body=%s", host, w.Code, w.Body.String())
		}
		// The Location should be the upstream IdP, not a client error redirect.
		loc := w.Header().Get("Location")
		if strings.Contains(loc, "error=invalid_target") {
			t.Fatalf("resource %q wrongly rejected: %q", host, loc)
		}
	}
}
