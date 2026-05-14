package jwt

import (
	"crypto/rsa"
	"encoding/base64"
	"math/big"
)

// JWK is a JSON Web Key entry as published at the jwks_uri endpoint. Only
// RSA verification keys are emitted by authlet.
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKS is the JSON Web Key Set wrapper served at jwks_uri.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// PublishJWKS builds a JWKS from a kid -> public key map. Each entry is
// tagged kty=RSA, use=sig, alg=RS256.
func PublishJWKS(keys map[string]*rsa.PublicKey) JWKS {
	out := JWKS{Keys: make([]JWK, 0, len(keys))}
	for kid, pk := range keys {
		out.Keys = append(out.Keys, JWK{
			Kty: "RSA",
			Use: "sig",
			Alg: "RS256",
			Kid: kid,
			N:   base64URLUint(pk.N),
			E:   base64URLUint(big.NewInt(int64(pk.E))),
		})
	}
	return out
}

func base64URLUint(i *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(i.Bytes())
}
