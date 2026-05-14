package as

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRegister_HappyPath(t *testing.T) {
	a := newTestAS(t)
	body := `{"redirect_uris":["https://claude.example/callback"],"client_name":"Claude"}`
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("status %d body=%s", w.Code, w.Body.String())
	}
	var resp dcrResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.ClientID == "" {
		t.Fatal("client_id missing")
	}
	if resp.TokenEndpointAuthMethod != "none" {
		t.Fatalf("expected public client, got %q", resp.TokenEndpointAuthMethod)
	}
}

func TestRegister_MissingRedirectURIs(t *testing.T) {
	a := newTestAS(t)
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(`{}`)))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status %d", w.Code)
	}
}

func TestRegister_BadJSON(t *testing.T) {
	a := newTestAS(t)
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/register", bytes.NewBufferString("not-json")))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status %d", w.Code)
	}
}

// TestRegister_RejectsFragmentInRedirectURI verifies that redirect URIs
// with a #fragment are rejected per RFC 7591 §2.3.1.
func TestRegister_RejectsFragmentInRedirectURI(t *testing.T) {
	a := newTestAS(t)
	body := `{"redirect_uris":["https://claude.example/callback#frag"]}`
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

// TestRegister_RejectsRelativeRedirectURI verifies that non-absolute
// redirect URIs are rejected.
func TestRegister_RejectsRelativeRedirectURI(t *testing.T) {
	a := newTestAS(t)
	body := `{"redirect_uris":["/relative/path"]}`
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

// TestRegister_RejectsUnsupportedGrantType asserts that grant_types not
// in {authorization_code, refresh_token} are rejected with
// invalid_client_metadata per RFC 7591.
func TestRegister_RejectsUnsupportedGrantType(t *testing.T) {
	a := newTestAS(t)
	body := `{"redirect_uris":["https://claude.example/cb"],"grant_types":["password"]}`
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", w.Code, w.Body.String())
	}
}
