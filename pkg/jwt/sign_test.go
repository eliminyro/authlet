package jwt

import (
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
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

// TestVerify_RejectsMissingExp asserts that a token carrying no exp claim
// is rejected with ErrMissingExp. RFC 9068 §4 requires access tokens to
// carry exp; without enforcement such a token would validate forever.
func TestVerify_RejectsMissingExp(t *testing.T) {
	k, _ := GenerateRSA()
	// Build a token with every standard claim EXCEPT exp.
	mc := jwtv5.MapClaims{
		"iss": "https://issuer.example",
		"sub": "u1",
		"aud": "https://rs.example/api",
		"iat": int64(1762000000),
		"jti": "id1",
	}
	tok := jwtv5.NewWithClaims(jwtv5.SigningMethodRS256, mc)
	tok.Header["kid"] = "kid1"
	signed, err := tok.SignedString(k)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Verify(signed, func(string) (*rsa.PublicKey, error) { return &k.PublicKey, nil }, VerifyOptions{
		Now: func() time.Time { return time.Unix(1762000010, 0) },
	})
	if !errors.Is(err, ErrMissingExp) {
		t.Fatalf("expected ErrMissingExp, got %v", err)
	}
}

// TestVerify_RejectsZeroExp asserts a token with an explicit exp of 0
// (non-positive) is also rejected, not treated as "no expiry".
func TestVerify_RejectsZeroExp(t *testing.T) {
	k, _ := GenerateRSA()
	c := newClaims()
	c.ExpiresAt = 0
	tok, _ := Sign(c, "kid1", k)
	_, err := Verify(tok, func(string) (*rsa.PublicKey, error) { return &k.PublicKey, nil }, VerifyOptions{
		Now: func() time.Time { return time.Unix(1762000010, 0) },
	})
	if !errors.Is(err, ErrMissingExp) {
		t.Fatalf("expected ErrMissingExp, got %v", err)
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

// TestVerify_RejectsTokenBeforeNbf asserts that a token whose nbf claim
// is in the future is rejected with ErrNotYetValid. authlet's AS does
// not mint nbf today; this guards pkg/rs which verifies tokens minted
// by other authorization servers that do.
func TestVerify_RejectsTokenBeforeNbf(t *testing.T) {
	k, _ := GenerateRSA()
	c := newClaims()
	c.NotBefore = 1762000500 // 500s after IssuedAt
	tok, _ := Sign(c, "kid1", k)
	_, err := Verify(tok, func(string) (*rsa.PublicKey, error) { return &k.PublicKey, nil }, VerifyOptions{
		Now: func() time.Time { return time.Unix(1762000100, 0) }, // before nbf
	})
	if !errors.Is(err, ErrNotYetValid) {
		t.Fatalf("expected ErrNotYetValid, got %v", err)
	}
}

// TestVerify_AcceptsTokenAfterNbf asserts that a token whose nbf is in
// the past is accepted (assuming exp etc. are also valid).
func TestVerify_AcceptsTokenAfterNbf(t *testing.T) {
	k, _ := GenerateRSA()
	c := newClaims()
	c.NotBefore = 1762000005
	tok, _ := Sign(c, "kid1", k)
	got, err := Verify(tok, func(string) (*rsa.PublicKey, error) { return &k.PublicKey, nil }, VerifyOptions{
		Now: func() time.Time { return time.Unix(1762000100, 0) }, // after nbf
	})
	if err != nil {
		t.Fatalf("expected accept, got %v", err)
	}
	if got.NotBefore != 1762000005 {
		t.Fatalf("nbf round-trip lost: got %d", got.NotBefore)
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
