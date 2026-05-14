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

	"github.com/eliminyro/authlet/pkg/jwt"
	"github.com/eliminyro/authlet/pkg/storage"
)

func newOIDCTestAS(t *testing.T) *AS {
	t.Helper()
	a := newTestAS(t)
	a.cfg.IDTokenClaims = func(userID string) (string, bool, string, string) {
		return "user-" + userID + "@example", true, "User " + userID, ""
	}
	return a
}

func seedAuthCodeWithScope(t *testing.T, a *AS, clientID, redirect, resource, challenge, scope string) string {
	t.Helper()
	plain, _ := randomID(32)
	_ = a.cfg.Storage.Codes().Save(context.Background(), storage.AuthCode{
		CodeHash:      hashCode(plain),
		ClientID:      clientID,
		UserID:        "user1",
		Resource:      resource,
		Scope:         scope,
		PKCEChallenge: challenge,
		PKCEMethod:    "S256",
		RedirectURI:   redirect,
		ExpiresAt:     time.Now().Add(10 * time.Minute),
	})
	return plain
}

func exchangeForToken(t *testing.T, a *AS, code, verifier, clientID, redirect, resource string) tokenResponse {
	t.Helper()
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", clientID)
	form.Set("code_verifier", verifier)
	form.Set("redirect_uri", redirect)
	form.Set("resource", resource)
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body=%s", w.Code, w.Body.String())
	}
	var tr tokenResponse
	_ = json.Unmarshal(w.Body.Bytes(), &tr)
	return tr
}

func TestToken_IDTokenIssuedWhenOpenidScope(t *testing.T) {
	a := newOIDCTestAS(t)
	cid := registerTestClient(t, a, "https://m/cb")
	verifier, challenge := pkcePair(t)
	code := seedAuthCodeWithScope(t, a, cid, "https://m/cb", "https://rs/api", challenge, "openid mcp")
	tr := exchangeForToken(t, a, code, verifier, cid, "https://m/cb", "https://rs/api")
	if tr.IDToken == "" {
		t.Fatalf("expected id_token, got empty: %+v", tr)
	}
	// Verify ID token signature + claims.
	c, err := jwt.Verify(tr.IDToken, a.cfg.KeyManager.PublicKeyFunc(context.Background()), jwt.VerifyOptions{
		ExpectedIssuer: a.cfg.Issuer,
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.Subject != "user1" {
		t.Fatalf("sub %q", c.Subject)
	}
	if c.Audience != cid {
		t.Fatalf("aud %q want %q (client_id)", c.Audience, cid)
	}
	if c.Extra["email"] != "user-user1@example" {
		t.Fatalf("email %v", c.Extra["email"])
	}
	if c.Extra["email_verified"] != true {
		t.Fatalf("email_verified %v", c.Extra["email_verified"])
	}
}

func TestToken_NoIDTokenWithoutOpenidScope(t *testing.T) {
	a := newOIDCTestAS(t)
	cid := registerTestClient(t, a, "https://m/cb")
	verifier, challenge := pkcePair(t)
	code := seedAuthCodeWithScope(t, a, cid, "https://m/cb", "https://rs/api", challenge, "mcp")
	tr := exchangeForToken(t, a, code, verifier, cid, "https://m/cb", "https://rs/api")
	if tr.IDToken != "" {
		t.Fatalf("expected no id_token, got %q", tr.IDToken)
	}
}
