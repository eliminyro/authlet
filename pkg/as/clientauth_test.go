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
	"golang.org/x/crypto/bcrypt"
)

func registerConfidentialClient(t *testing.T, a *AS, clientID, redirect, secret string) {
	t.Helper()
	hash, _ := bcrypt.GenerateFromPassword([]byte(secret), 4)
	_ = a.cfg.Storage.Clients().Create(context.Background(), storage.Client{
		ClientID:                clientID,
		SecretHash:              hash,
		TokenEndpointAuthMethod: "client_secret_basic",
		RedirectURIs:            []string{redirect},
		CreatedAt:               time.Now(),
		ExpiresAt:               time.Now().Add(24 * time.Hour),
	})
}

func TestToken_ConfidentialClientNoBasicAuthRejected(t *testing.T) {
	a := newTestAS(t)
	registerConfidentialClient(t, a, "mem-mcp", "https://m/cb", "super-secret")
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", "mem-mcp")
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", w.Code)
	}
}

func TestToken_ConfidentialClientWrongSecretRejected(t *testing.T) {
	a := newTestAS(t)
	registerConfidentialClient(t, a, "mem-mcp", "https://m/cb", "super-secret")
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("mem-mcp", "WRONG")
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", w.Code)
	}
}

func TestToken_ConfidentialClientCorrectSecretReachesGrantHandler(t *testing.T) {
	a := newTestAS(t)
	registerConfidentialClient(t, a, "mem-mcp", "https://m/cb", "super-secret")
	form := url.Values{}
	form.Set("grant_type", "unknown") // forces grant-handler 400 once auth passes
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("mem-mcp", "super-secret")
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status %d body=%s", w.Code, w.Body.String())
	}
}

// TestToken_ConfidentialClientURLEncodedSecret asserts that Basic Auth
// credentials are URL-decoded per RFC 6749 §2.3.1 before bcrypt-compare.
func TestToken_ConfidentialClientURLEncodedSecret(t *testing.T) {
	a := newTestAS(t)
	// Secret contains characters that should be percent-encoded in transit.
	realSecret := "s p:c!"
	registerConfidentialClient(t, a, "mem-mcp", "https://m/cb", realSecret)
	form := url.Values{}
	form.Set("grant_type", "unknown")
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Send Basic Auth using the percent-encoded form, as per spec.
	req.SetBasicAuth("mem-mcp", url.QueryEscape(realSecret))
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)
	// 400 means auth passed (then grant-handler rejected). 401 means we
	// failed the bcrypt comparison.
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 after auth success, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestToken_PublicClientNoBasicAuthAllowed(t *testing.T) {
	a := newTestAS(t)
	cid := registerTestClient(t, a, "https://claude/cb")
	form := url.Values{}
	form.Set("grant_type", "unknown")
	form.Set("client_id", cid)
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)
	// Auth passes; grant-handler returns 400 for unknown grant_type.
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status %d", w.Code)
	}
}
