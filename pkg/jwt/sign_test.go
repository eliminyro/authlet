package jwt

import (
	"crypto/rsa"
	"errors"
	"testing"
	"time"
)

func newClaims() Claims {
	return Claims{
		Issuer: "https://issuer.example", Subject: "u1", Audience: "https://rs.example/api",
		ClientID: "c1", Scope: "mcp", IssuedAt: 1762000000, ExpiresAt: 1762003600, JTI: "id1",
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	k, _ := GenerateRSA()
	tok, err := Sign(newClaims(), "kid1", k)
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(kid string) (*rsa.PublicKey, error) {
		if kid != "kid1" {
			t.Fatalf("bad kid: %q", kid)
		}
		return &k.PublicKey, nil
	}
	c, err := Verify(tok, resolve, VerifyOptions{
		ExpectedIssuer: "https://issuer.example", ExpectedAudience: "https://rs.example/api",
		Now: func() time.Time { return time.Unix(1762000010, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.Subject != "u1" {
		t.Fatalf("sub mismatch %q", c.Subject)
	}
}

func TestVerifyWrongIssuer(t *testing.T) {
	k, _ := GenerateRSA()
	tok, _ := Sign(newClaims(), "kid1", k)
	_, err := Verify(tok, func(string) (*rsa.PublicKey, error) { return &k.PublicKey, nil }, VerifyOptions{
		ExpectedIssuer: "https://other", Now: func() time.Time { return time.Unix(1762000010, 0) },
	})
	if !errors.Is(err, ErrInvalidIssuer) {
		t.Fatalf("got %v", err)
	}
}

func TestVerifyWrongAudience(t *testing.T) {
	k, _ := GenerateRSA()
	tok, _ := Sign(newClaims(), "kid1", k)
	_, err := Verify(tok, func(string) (*rsa.PublicKey, error) { return &k.PublicKey, nil }, VerifyOptions{
		ExpectedAudience: "https://wrong", Now: func() time.Time { return time.Unix(1762000010, 0) },
	})
	if !errors.Is(err, ErrInvalidAud) {
		t.Fatalf("got %v", err)
	}
}

func TestVerifyExpired(t *testing.T) {
	k, _ := GenerateRSA()
	tok, _ := Sign(newClaims(), "kid1", k)
	_, err := Verify(tok, func(string) (*rsa.PublicKey, error) { return &k.PublicKey, nil }, VerifyOptions{
		Now: func() time.Time { return time.Unix(1762003600, 0) }, // exactly exp
	})
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("got %v", err)
	}
}

func TestVerifyUnknownKID(t *testing.T) {
	k, _ := GenerateRSA()
	tok, _ := Sign(newClaims(), "kid1", k)
	_, err := Verify(tok, func(string) (*rsa.PublicKey, error) { return nil, errors.New("nope") }, VerifyOptions{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestSignWithExtraClaims(t *testing.T) {
	k, _ := GenerateRSA()
	c := newClaims()
	c.Extra = map[string]any{"tenant_id": "t1"}
	tok, _ := Sign(c, "kid1", k)
	got, err := Verify(tok, func(string) (*rsa.PublicKey, error) { return &k.PublicKey, nil }, VerifyOptions{
		Now: func() time.Time { return time.Unix(1762000010, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Extra["tenant_id"] != "t1" {
		t.Fatalf("extra claim lost: %+v", got.Extra)
	}
}
