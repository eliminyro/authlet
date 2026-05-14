package jwt

import (
	"crypto/rsa"
	"testing"
)

func TestGenerateRSAReturns2048Bit(t *testing.T) {
	k, err := GenerateRSA()
	if err != nil {
		t.Fatal(err)
	}
	if k.N.BitLen() != RSAKeyBits {
		t.Fatalf("got %d bits, want %d", k.N.BitLen(), RSAKeyBits)
	}
}

func TestPrivatePEMRoundTrip(t *testing.T) {
	k, _ := GenerateRSA()
	p, err := MarshalPrivatePEM(k)
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParsePrivatePEM(p)
	if err != nil {
		t.Fatal(err)
	}
	if back.N.Cmp(k.N) != 0 {
		t.Fatal("modulus mismatch after roundtrip")
	}
}

func TestPublicPEMRoundTrip(t *testing.T) {
	k, _ := GenerateRSA()
	p, err := MarshalPublicPEM(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParsePublicPEM(p)
	if err != nil {
		t.Fatal(err)
	}
	if !back.Equal(&k.PublicKey) {
		t.Fatal("public key mismatch")
	}
}

func TestParsePrivatePEM_BadInput(t *testing.T) {
	if _, err := ParsePrivatePEM([]byte("not pem")); err == nil {
		t.Fatal("expected error")
	}
}

var _ = rsa.PrivateKey{} // keep crypto/rsa imported in tests intentionally
