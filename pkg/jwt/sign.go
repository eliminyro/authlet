package jwt

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
)

// Claims is the set of JWT claims authlet's AS mints. Apps may inject
// additional custom claims via Extra; reserved standard claim names cannot
// be overridden through Extra.
type Claims struct {
	Issuer    string         `json:"iss"`
	Subject   string         `json:"sub"`
	Audience  string         `json:"aud"`
	ClientID  string         `json:"client_id"`
	Scope     string         `json:"scope"`
	IssuedAt  int64          `json:"iat"`
	ExpiresAt int64          `json:"exp"`
	JTI       string         `json:"jti"`
	Extra     map[string]any `json:"-"`
}

// Sign returns a signed RS256 JWT carrying the given claims and kid header.
func Sign(c Claims, kid string, priv *rsa.PrivateKey) (string, error) {
	mc := jwtv5.MapClaims{
		"iss":       c.Issuer,
		"sub":       c.Subject,
		"aud":       c.Audience,
		"client_id": c.ClientID,
		"scope":     c.Scope,
		"iat":       c.IssuedAt,
		"exp":       c.ExpiresAt,
		"jti":       c.JTI,
	}
	for k, v := range c.Extra {
		if _, reserved := mc[k]; reserved {
			continue
		}
		mc[k] = v
	}
	tok := jwtv5.NewWithClaims(jwtv5.SigningMethodRS256, mc)
	tok.Header["kid"] = kid
	return tok.SignedString(priv)
}

// PublicKeyFunc resolves a kid header value to the public key that signed it.
type PublicKeyFunc func(kid string) (*rsa.PublicKey, error)

// Sentinel errors returned by Verify.
var (
	// ErrUnknownKID is returned when the resolver cannot find a key for the
	// kid present in the token header.
	ErrUnknownKID = errors.New("jwt: unknown kid")
	// ErrInvalidIssuer is returned when the token's iss claim does not match
	// VerifyOptions.ExpectedIssuer.
	ErrInvalidIssuer = errors.New("jwt: invalid issuer")
	// ErrInvalidAud is returned when the token's aud claim does not match
	// VerifyOptions.ExpectedAudience.
	ErrInvalidAud = errors.New("jwt: invalid audience")
	// ErrExpired is returned when the token's exp claim is at or before
	// VerifyOptions.Now.
	ErrExpired = errors.New("jwt: expired")
)

// VerifyOptions narrows what Verify will accept. Zero values disable the
// corresponding check; Now defaults to time.Now.
type VerifyOptions struct {
	ExpectedIssuer   string
	ExpectedAudience string
	Now              func() time.Time
}

// Verify parses tokenString, checks the RS256 signature against the
// kid-resolved public key, and validates the iss, aud and exp claims.
func Verify(tokenString string, resolve PublicKeyFunc, opts VerifyOptions) (Claims, error) {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	parser := jwtv5.NewParser(
		jwtv5.WithValidMethods([]string{"RS256"}),
		jwtv5.WithoutClaimsValidation(),
	)
	tok, err := parser.Parse(tokenString, func(t *jwtv5.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		pk, err := resolve(kid)
		if err != nil {
			return nil, ErrUnknownKID
		}
		return pk, nil
	})
	if err != nil {
		return Claims{}, fmt.Errorf("parse: %w", err)
	}
	mc, ok := tok.Claims.(jwtv5.MapClaims)
	if !ok || !tok.Valid {
		return Claims{}, errors.New("jwt: invalid token")
	}
	c := Claims{
		Issuer:    asString(mc["iss"]),
		Subject:   asString(mc["sub"]),
		Audience:  asString(mc["aud"]),
		ClientID:  asString(mc["client_id"]),
		Scope:     asString(mc["scope"]),
		IssuedAt:  asInt64(mc["iat"]),
		ExpiresAt: asInt64(mc["exp"]),
		JTI:       asString(mc["jti"]),
		Extra:     map[string]any{},
	}
	for k, v := range mc {
		switch k {
		case "iss", "sub", "aud", "client_id", "scope", "iat", "exp", "jti":
			continue
		default:
			c.Extra[k] = v
		}
	}
	if opts.ExpectedIssuer != "" && c.Issuer != opts.ExpectedIssuer {
		return c, ErrInvalidIssuer
	}
	if opts.ExpectedAudience != "" && c.Audience != opts.ExpectedAudience {
		return c, ErrInvalidAud
	}
	if c.ExpiresAt > 0 && opts.Now().Unix() >= c.ExpiresAt {
		return c, ErrExpired
	}
	return c, nil
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}

func asInt64(v any) int64 {
	switch x := v.(type) {
	case float64:
		return int64(x)
	case int64:
		return x
	case int:
		return int64(x)
	}
	return 0
}
