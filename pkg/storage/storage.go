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
	// ConsumeOnce atomically reads and deletes a code by its hash,
	// returning the AuthCode value if it was both present and not
	// expired.
	//
	// Returns:
	//   - (*AuthCode, nil) — code existed, not expired; entry now deleted
	//   - (nil, ErrNotFound) — code did not exist (or was already
	//     consumed by a previous successful ConsumeOnce; memstore deletes
	//     on consume so replay yields ErrNotFound)
	//   - (nil, ErrAlreadyConsumed) — code existed but had expired;
	//     the entry is also deleted as a side-effect, so a subsequent
	//     call for the same hash returns ErrNotFound
	//
	// Callers should treat both ErrNotFound and ErrAlreadyConsumed as
	// "code is no longer valid"; the distinction is informational
	// (useful for diagnostics).
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
