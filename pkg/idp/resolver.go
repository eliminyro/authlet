package idp

import (
	"context"
	"errors"
)

// ErrNoUser indicates that the upstream claims did not resolve to a known
// internal user.
var ErrNoUser = errors.New("idp: no matching user")

// UserResolver maps upstream OIDC claims to an internal user ID.
// Apps implement this against their own user table.
type UserResolver interface {
	Resolve(ctx context.Context, c Claims) (userID string, err error)
}

// UserResolverFunc is a function adapter that lets a plain function satisfy
// the UserResolver interface.
type UserResolverFunc func(ctx context.Context, c Claims) (string, error)

// Resolve calls f(ctx, c).
func (f UserResolverFunc) Resolve(ctx context.Context, c Claims) (string, error) {
	return f(ctx, c)
}
