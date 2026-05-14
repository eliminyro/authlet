package crypto

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
)

func mustKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, KeySize)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := mustKey(t)
	pt := []byte("hello authlet")
	ct, err := Encrypt(key, pt)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decrypt(key, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("roundtrip mismatch: %q vs %q", got, pt)
	}
}

func TestEncryptProducesDifferentCiphertextEachCall(t *testing.T) {
	key := mustKey(t)
	pt := []byte("same plaintext")
	a, _ := Encrypt(key, pt)
	b, _ := Encrypt(key, pt)
	if bytes.Equal(a, b) {
		t.Fatal("nonce reuse — ciphertexts must differ")
	}
}

func TestWrongKeyFailsAuth(t *testing.T) {
	k1, k2 := mustKey(t), mustKey(t)
	ct, _ := Encrypt(k1, []byte("secret"))
	if _, err := Decrypt(k2, ct); err == nil {
		t.Fatal("expected decrypt failure under wrong key")
	}
}

func TestKeyWrongSize(t *testing.T) {
	short := make([]byte, 16)
	if _, err := Encrypt(short, []byte("x")); !errors.Is(err, ErrKeySize) {
		t.Fatalf("expected ErrKeySize, got %v", err)
	}
}

func TestCiphertextTooShort(t *testing.T) {
	if _, err := Decrypt(mustKey(t), []byte{1, 2, 3}); !errors.Is(err, ErrCiphertext) {
		t.Fatalf("expected ErrCiphertext, got %v", err)
	}
}
