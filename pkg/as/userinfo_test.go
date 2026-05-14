package as

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/eliminyro/authlet/pkg/jwt"
)

func TestUserinfo_NoBearerReturns401(t *testing.T) {
	a := newTestAS(t)
	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", w.Code)
	}
}

func TestUserinfo_ValidTokenReturnsClaims(t *testing.T) {
	a := newTestAS(t)
	priv, kid, err := a.cfg.KeyManager.Signer(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := jwt.Sign(jwt.Claims{
		Issuer:    a.cfg.Issuer,
		Subject:   "user-9",
		Audience:  "https://rs/api",
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		Extra:     map[string]any{"email": "u@example.test"},
	}, kid, priv)
	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if out["sub"] != "user-9" || out["email"] != "u@example.test" {
		t.Fatalf("claims wrong: %+v", out)
	}
}
