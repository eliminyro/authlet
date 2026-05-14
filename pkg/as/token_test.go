package as

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/eliminyro/authlet/pkg/storage"
)

func pkcePair(t *testing.T) (verifier, challenge string) {
	t.Helper()
	verifier = "the-verifier-must-be-43-to-128-chars-base64url-12345"
	sum := sha256.Sum256([]byte(verifier))
	challenge = strings.TrimRight(base64.URLEncoding.EncodeToString(sum[:]), "=")
	challenge = strings.ReplaceAll(challenge, "+", "-")
	challenge = strings.ReplaceAll(challenge, "/", "_")
	return
}

func seedAuthCode(t *testing.T, a *AS, clientID, redirect, resource, challenge string) string {
	t.Helper()
	plain, _ := randomID(32)
	_ = a.cfg.Storage.Codes().Save(context.Background(), storage.AuthCode{
		CodeHash:      hashCode(plain),
		ClientID:      clientID,
		UserID:        "user1",
		Resource:      resource,
		Scope:         "mcp",
		PKCEChallenge: challenge,
		PKCEMethod:    "S256",
		RedirectURI:   redirect,
		ExpiresAt:     time.Now().Add(10 * time.Minute),
	})
	return plain
}

func TestToken_AuthCodeHappyPath(t *testing.T) {
	a := newTestAS(t)
	cid := registerTestClient(t, a, "https://claude/cb")
	verifier, challenge := pkcePair(t)
	code := seedAuthCode(t, a, cid, "https://claude/cb", "https://rs/api", challenge)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", cid)
	form.Set("code_verifier", verifier)
	form.Set("redirect_uri", "https://claude/cb")
	form.Set("resource", "https://rs/api")

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body=%s", w.Code, w.Body.String())
	}
	var tr tokenResponse
	_ = json.Unmarshal(w.Body.Bytes(), &tr)
	if tr.AccessToken == "" || tr.RefreshToken == "" {
		t.Fatalf("missing tokens: %+v", tr)
	}
	if tr.TokenType != "Bearer" || tr.ExpiresIn <= 0 {
		t.Fatalf("bad shape: %+v", tr)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("missing Cache-Control: no-store, got %q", w.Header().Get("Cache-Control"))
	}
	if w.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("missing Pragma: no-cache, got %q", w.Header().Get("Pragma"))
	}
}

// TestToken_AdditionalClaimsPanicRecovered asserts a panicking
// AdditionalClaims hook is recovered and the token is still issued.
func TestToken_AdditionalClaimsPanicRecovered(t *testing.T) {
	a := newTestAS(t)
	a.cfg.AdditionalClaims = func(userID, clientID, resource string) map[string]any {
		panic("boom")
	}
	cid := registerTestClient(t, a, "https://claude/cb")
	verifier, challenge := pkcePair(t)
	code := seedAuthCode(t, a, cid, "https://claude/cb", "https://rs/api", challenge)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", cid)
	form.Set("code_verifier", verifier)
	form.Set("redirect_uri", "https://claude/cb")
	form.Set("resource", "https://rs/api")

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (panic recovered), got %d body=%s", w.Code, w.Body.String())
	}
}

// TestToken_ErrorResponseHasCacheControl verifies the no-store/no-cache
// headers are also set on /token error responses (RFC 6749 §5.1).
func TestToken_ErrorResponseHasCacheControl(t *testing.T) {
	a := newTestAS(t)
	cid := registerTestClient(t, a, "https://claude/cb")
	form := url.Values{}
	form.Set("grant_type", "unknown")
	form.Set("client_id", cid)
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("missing Cache-Control on error, got %q", w.Header().Get("Cache-Control"))
	}
	if w.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("missing Pragma on error, got %q", w.Header().Get("Pragma"))
	}
}

func TestToken_RejectsBadPKCE(t *testing.T) {
	a := newTestAS(t)
	cid := registerTestClient(t, a, "https://claude/cb")
	_, challenge := pkcePair(t)
	code := seedAuthCode(t, a, cid, "https://claude/cb", "https://rs/api", challenge)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", cid)
	form.Set("code_verifier", "wrong-verifier")
	form.Set("redirect_uri", "https://claude/cb")
	form.Set("resource", "https://rs/api")

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status %d", w.Code)
	}
}

func TestToken_RejectsResourceMismatch(t *testing.T) {
	a := newTestAS(t)
	cid := registerTestClient(t, a, "https://claude/cb")
	verifier, challenge := pkcePair(t)
	code := seedAuthCode(t, a, cid, "https://claude/cb", "https://rs/api", challenge)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", cid)
	form.Set("code_verifier", verifier)
	form.Set("redirect_uri", "https://claude/cb")
	form.Set("resource", "https://OTHER/api")

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status %d", w.Code)
	}
}

func TestToken_CodeIsSingleUse(t *testing.T) {
	a := newTestAS(t)
	cid := registerTestClient(t, a, "https://claude/cb")
	verifier, challenge := pkcePair(t)
	code := seedAuthCode(t, a, cid, "https://claude/cb", "https://rs/api", challenge)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", cid)
	form.Set("code_verifier", verifier)
	form.Set("redirect_uri", "https://claude/cb")
	form.Set("resource", "https://rs/api")

	for i, want := range []int{http.StatusOK, http.StatusBadRequest} {
		req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		a.Handler().ServeHTTP(w, req)
		if w.Code != want {
			t.Fatalf("iter %d: status %d want %d", i, w.Code, want)
		}
	}
}
