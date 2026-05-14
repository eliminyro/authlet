package storage

import (
	"context"
	"errors"
	"time"
)

// Sentinel errors returned by storage implementations. Use errors.Is to
// detect them; concrete drivers may wrap these with additional context.
var (
	ErrNotFound        = errors.New("storage: not found")
	ErrAlreadyExists   = errors.New("storage: already exists")
	ErrAlreadyConsumed = errors.New("storage: already consumed")
	ErrFamilyRevoked   = errors.New("storage: token family revoked")
)

// Storage is the umbrella interface aggregating every sub-store the
// authorization server needs. Concrete drivers (memstore, sqlite, ...)
// implement this and expose each sub-store via its accessor.
type Storage interface {
	Clients() ClientStore
	Codes() CodeStore
	RefreshTokens() RefreshTokenStore
	SigningKeys() SigningKeyStore
}

// ClientStore persists registered OAuth clients (public via DCR or
// pre-registered confidential).
type ClientStore interface {
	Create(ctx context.Context, c Client) error
	Get(ctx context.Context, clientID string) (*Client, error)
	Touch(ctx context.Context, clientID string) error
	DeleteExpired(ctx context.Context, olderThan time.Time) (int, error)
}

// CodeStore persists short-lived authorization codes. ConsumeOnce must be
// atomic — exactly one caller can redeem a given code.
type CodeStore interface {
	Save(ctx context.Context, code AuthCode) error
	ConsumeOnce(ctx context.Context, codeHash string) (*AuthCode, error)
	DeleteExpired(ctx context.Context, before time.Time) (int, error)
}

// RefreshTokenStore persists refresh tokens and the revocation state of
// their families. Reuse detection: a second MarkUsed on the same hash
// returns ErrAlreadyConsumed, and the caller is expected to RevokeFamily.
type RefreshTokenStore interface {
	Save(ctx context.Context, rt RefreshToken) error
	Get(ctx context.Context, tokenHash string) (*RefreshToken, error)
	MarkUsed(ctx context.Context, tokenHash string, replacedBy string) error
	RevokeFamily(ctx context.Context, familyID string) error
	IsFamilyRevoked(ctx context.Context, familyID string) (bool, error)
	DeleteExpired(ctx context.Context, before time.Time) (int, error)
}

// SigningKeyStore persists RSA signing keys. Exactly one row is active at
// a time; older keys stay queryable for verification until retired.
type SigningKeyStore interface {
	ListActive(ctx context.Context) ([]SigningKey, error)
	GetSigner(ctx context.Context) (SigningKey, error)
	Insert(ctx context.Context, k SigningKey) error
	Retire(ctx context.Context, id string, at time.Time) error
}
