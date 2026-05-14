// Package jwt provides RS256 signing, JWKS publication, and 30-day key
// rotation for authlet's authorization server. Private keys are stored
// encrypted via pkg/crypto.
package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// RSAKeyBits is the modulus size used for newly generated signing keys.
const RSAKeyBits = 2048

// Sentinel errors for PEM parsing.
var (
	// ErrPEMDecode is returned when input bytes contain no decodable PEM block.
	ErrPEMDecode = errors.New("jwt: pem decode failed")
	// ErrPEMType is returned when the PEM block type is not the one expected
	// (e.g. parsing a public key from a "PRIVATE KEY" block).
	ErrPEMType = errors.New("jwt: unexpected pem block type")
)

// GenerateRSA creates a new RSA-2048 key pair suitable for RS256 signing.
func GenerateRSA() (*rsa.PrivateKey, error) {
	k, err := rsa.GenerateKey(rand.Reader, RSAKeyBits)
	if err != nil {
		return nil, fmt.Errorf("rsa: %w", err)
	}
	return k, nil
}

// MarshalPrivatePEM returns PKCS#8 PEM bytes for the given RSA private key.
func MarshalPrivatePEM(k *rsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, fmt.Errorf("marshal pkcs8: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// MarshalPublicPEM returns PKIX PEM bytes for the given RSA public key.
func MarshalPublicPEM(k *rsa.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		return nil, fmt.Errorf("marshal pkix: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// ParsePrivatePEM parses PKCS#8 PEM bytes into an RSA private key.
func ParsePrivatePEM(p []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(p)
	if block == nil {
		return nil, ErrPEMDecode
	}
	if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("%w: %s", ErrPEMType, block.Type)
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse pkcs8: %w", err)
	}
	rsk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: not rsa", ErrPEMType)
	}
	return rsk, nil
}

// ParsePublicPEM parses PKIX PEM bytes into an RSA public key.
func ParsePublicPEM(p []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(p)
	if block == nil {
		return nil, ErrPEMDecode
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("%w: %s", ErrPEMType, block.Type)
	}
	pk, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse pkix: %w", err)
	}
	rpk, ok := pk.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: not rsa", ErrPEMType)
	}
	return rpk, nil
}
