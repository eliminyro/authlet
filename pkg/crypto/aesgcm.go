// Package crypto provides an AES-GCM helper for encrypting small at-rest
// payloads such as RSA private keys. Callers bring their own 32-byte master
// key (typically loaded from a secret store).
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// KeySize is the required master key length in bytes (AES-256).
const KeySize = 32

// Sentinel errors returned by Encrypt and Decrypt.
var (
	ErrKeySize    = errors.New("crypto: master key must be 32 bytes")
	ErrCiphertext = errors.New("crypto: ciphertext too short")
)

// Encrypt seals plaintext with key, returning nonce||ciphertext||tag.
// Callers store the returned slice as-is.
func Encrypt(key, plaintext []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, ErrKeySize
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("rand: %w", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt reverses Encrypt.
func Decrypt(key, ct []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, ErrKeySize
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	if len(ct) < gcm.NonceSize() {
		return nil, ErrCiphertext
	}
	nonce, body := ct[:gcm.NonceSize()], ct[gcm.NonceSize():]
	pt, err := gcm.Open(nil, nonce, body, nil)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	return pt, nil
}
