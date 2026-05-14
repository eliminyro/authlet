package as

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMetadataHandler_ShapeAndIssuer(t *testing.T) {
	a := newTestAS(t)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	w := httptest.NewRecorder()
	a.MetadataHandler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	var md ASMetadata
	_ = json.Unmarshal(w.Body.Bytes(), &md)
	if md.Issuer != "https://example.test" {
		t.Fatalf("issuer %q", md.Issuer)
	}
	if md.AuthorizationEndpoint != "https://example.test/oauth/authorize" {
		t.Fatalf("authorize %q", md.AuthorizationEndpoint)
	}
	if len(md.CodeChallengeMethodsSupported) == 0 || md.CodeChallengeMethodsSupported[0] != "S256" {
		t.Fatalf("pkce %+v", md.CodeChallengeMethodsSupported)
	}
}

func TestJWKSHandler_ReturnsPublishedKeys(t *testing.T) {
	a := newTestAS(t)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()
	a.JWKSHandler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	var jwks struct {
		Keys []map[string]any `json:"keys"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &jwks)
	if len(jwks.Keys) == 0 {
		t.Fatal("expected at least one key")
	}
	if jwks.Keys[0]["alg"] != "RS256" {
		t.Fatalf("alg %v", jwks.Keys[0]["alg"])
	}
}

func TestOIDCMetadataHandler_MatchesAS(t *testing.T) {
	a := newTestAS(t)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()
	a.OIDCMetadataHandler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	var md ASMetadata
	_ = json.Unmarshal(w.Body.Bytes(), &md)
	if md.JWKSURI != "https://example.test/.well-known/jwks.json" {
		t.Fatalf("jwks_uri %q", md.JWKSURI)
	}
}
