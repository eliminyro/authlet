package jwt

import (
	"crypto/rsa"
	"testing"
)

func TestPublishJWKS_KeysAndShape(t *testing.T) {
	k, _ := GenerateRSA()
	jwks := PublishJWKS(map[string]*rsa.PublicKey{"k1": &k.PublicKey})
	if len(jwks.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(jwks.Keys))
	}
	got := jwks.Keys[0]
	if got.Kty != "RSA" || got.Use != "sig" || got.Alg != "RS256" {
		t.Fatalf("header fields wrong: %+v", got)
	}
	if got.Kid != "k1" {
		t.Fatalf("kid mismatch: %q", got.Kid)
	}
	if got.N == "" || got.E == "" {
		t.Fatal("n/e empty")
	}
}

func TestPublishJWKS_EmptyMap(t *testing.T) {
	jwks := PublishJWKS(map[string]*rsa.PublicKey{})
	if len(jwks.Keys) != 0 {
		t.Fatalf("expected empty, got %+v", jwks)
	}
}
