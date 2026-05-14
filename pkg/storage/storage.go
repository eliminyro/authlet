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
	// Get returns the client by ID or ErrNotFound when the ID is unknown.
	Get(ctx context.Context, clientID string) (*Client, error)
	// Touch updates the client's LastUsedAt timestamp. It returns
	// ErrNotFound when the client does not exist.
	Touch(ctx context.Context, clientID string) error
	DeleteExpired(ctx context.Context, olderThan time.Time) (int, error)
}

// CodeStore persists short-lived authorization codes. ConsumeOnce must be
// atomic — exactly one caller can redeem a given code.
type CodeStore interface {
	Save(ctx context.Context, code AuthCode) error
	// ConsumeOnce atomically reads and deletes (or marks consumed) the
	// code identified by codeHash, returning it on success.
	//
	// It returns ErrNotFound when the code does not exist (including
	// the case where it was previously consumed by a delete-on-read
	// implementation such as memstore).
	//
	// It returns ErrAlreadyConsumed only when the implementation tracks
	// consumed-but-undeleted state. Memstore deletes on consume, so
	// replay attempts produce ErrNotFound rather than ErrAlreadyConsumed.
	// Callers should treat both errors as "code is no longer valid".
	ConsumeOnce(ctx context.Context, codeHash string) (*AuthCode, error)
	DeleteExpired(ctx context.Context, before time.Time) (int, error)
}

// RefreshTokenStore persists refresh tokens and the revocation state of
// their families. Reuse detection: a second MarkUsed on the same hash
// returns ErrAlreadyConsumed, and the caller MUST then call RevokeFamily
// to invalidate the whole chain.
type RefreshTokenStore interface {
	Save(ctx context.Context, rt RefreshToken) error
	Get(ctx context.Context, tokenHash string) (*RefreshToken, error)
	// MarkUsed atomically transitions the token at tokenHash from
	// "active" to "replaced by replacedBy". It MUST be a single
	// check-and-set so two concurrent rotations cannot both succeed.
	//
	// Returns ErrAlreadyConsumed on the second (and later) attempt for
	// the same token; the caller MUST then call RevokeFamily(rt.FamilyID)
	// to invalidate the whole token chain per reuse-detection semantics.
	// Returns ErrNotFound when the token does not exist.
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
	// Insert persists the key. When k.IsActive is true the
	// implementation MUST atomically deactivate any prior active row in
	// the same transaction. Implementations without atomic transactions
	// may briefly produce a window with zero active keys, which callers
	// (jwt.Manager) treat as a transient ErrNotFound and retry.
	Insert(ctx context.Context, k SigningKey) error
	Retire(ctx context.Context, id string, at time.Time) error
}
