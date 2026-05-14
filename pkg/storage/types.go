package storage

import "time"

// Client is a registered OAuth client. Created either by Dynamic Client
// Registration (public, PKCE-only) or pre-registered (confidential).
type Client struct {
	ClientID string
	// SecretHash is the bcrypt hash of the client's secret. Empty for
	// public (DCR'd) clients that authenticate via PKCE only. Set for
	// pre-registered confidential clients using client_secret_basic.
	SecretHash []byte
	// TokenEndpointAuthMethod is "none" for public clients, or
	// "client_secret_basic" for confidential clients.
	TokenEndpointAuthMethod string
	RedirectURIs            []string
	Metadata                map[string]any
	CreatedAt               time.Time
	LastUsedAt              time.Time
	ExpiresAt               time.Time
}

// AuthCode is a one-time authorization code issued from /authorize and
// redeemed at /token. Stored by hash; the plaintext is delivered to the
// client and never persisted.
type AuthCode struct {
	CodeHash      string
	ClientID      string
	UserID        string
	Resource      string
	Scope         string
	PKCEChallenge string
	PKCEMethod    string
	RedirectURI   string
	ExpiresAt     time.Time
}

// RefreshToken is a long-lived token used to mint new access tokens.
// FamilyID groups rotated tokens so reuse detection can revoke the whole
// chain. Stored by hash.
type RefreshToken struct {
	TokenHash  string
	FamilyID   string
	ClientID   string
	UserID     string
	Resource   string
	Scope      string
	ReplacedBy string
	RevokedAt  *time.Time
	ExpiresAt  time.Time
}

// SigningKey is an RSA keypair used to sign issued JWTs. Only one key is
// active at a time; older keys remain available for verification until
// RetiresAt passes.
type SigningKey struct {
	ID                  string
	Algorithm           string
	PublicPEM           []byte
	PrivatePEMEncrypted []byte
	IsActive            bool
	CreatedAt           time.Time
	RetiresAt           *time.Time
}
