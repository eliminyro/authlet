// Package as implements an OAuth 2.1 / OIDC Authorization Server.
//
// Embed it in your application by passing a Config to New, then mounting
// the returned handler under /oauth and wiring the well-known endpoints
// at the host root.
package as

import (
	"errors"
	"time"

	"github.com/eliminyro/authlet/pkg/idp"
	"github.com/eliminyro/authlet/pkg/jwt"
	"github.com/eliminyro/authlet/pkg/storage"
)

// Config configures an authorization server.
type Config struct {
	// Issuer is the public base URL, e.g. https://hilo.eliminyro.me.
	// All emitted JWTs use this as `iss`. Must not have a trailing slash.
	Issuer string

	// PathPrefix is the mount path under Issuer where the AS lives,
	// e.g. "/oauth". Must start with "/" and have no trailing slash.
	PathPrefix string

	// Upstream is the upstream OIDC provider used to authenticate users.
	Upstream *idp.OIDCProvider

	// UserResolver maps upstream OIDC claims to an internal user ID.
	UserResolver idp.UserResolver

	// Storage provides the four sub-stores.
	Storage storage.Storage

	// KeyManager owns the active signing key.
	KeyManager *jwt.Manager

	// AccessTokenTTL defaults to 1h.
	AccessTokenTTL time.Duration

	// RefreshTokenTTL defaults to 30d.
	RefreshTokenTTL time.Duration

	// AuthCodeTTL defaults to 10m.
	AuthCodeTTL time.Duration

	// ClientTTL defaults to 90d sliding (DeleteExpired honors LastUsedAt).
	ClientTTL time.Duration

	// StateCookieTTL defaults to 10m.
	StateCookieTTL time.Duration

	// AdditionalClaims is called when minting an access token. It returns
	// app-specific claims to merge into the JWT (e.g. tenant_id for Memory).
	// May be nil.
	AdditionalClaims func(userID, clientID, resource string) map[string]any

	// IDTokenClaims is called when the AS needs to mint an ID token (i.e.
	// when the original auth request scope contained "openid"). It returns
	// the standard OIDC ID token claims for the given user. If nil, the ID
	// token is minted with only sub + iss + aud + iat + exp.
	IDTokenClaims func(userID string) (email string, emailVerified bool, name, picture string)
}

// ErrIssuerRequired indicates Config.Issuer was not set.
var ErrIssuerRequired = errors.New("as: Issuer required")

// ErrUpstreamRequired indicates Config.Upstream was not set.
var ErrUpstreamRequired = errors.New("as: Upstream required")

// ErrUserResolverRequired indicates Config.UserResolver was not set.
var ErrUserResolverRequired = errors.New("as: UserResolver required")

// ErrStorageRequired indicates Config.Storage was not set.
var ErrStorageRequired = errors.New("as: Storage required")

// ErrKeyManagerRequired indicates Config.KeyManager was not set.
var ErrKeyManagerRequired = errors.New("as: KeyManager required")

func (c *Config) defaults() {
	if c.AccessTokenTTL == 0 {
		c.AccessTokenTTL = time.Hour
	}
	if c.RefreshTokenTTL == 0 {
		c.RefreshTokenTTL = 30 * 24 * time.Hour
	}
	if c.AuthCodeTTL == 0 {
		c.AuthCodeTTL = 10 * time.Minute
	}
	if c.ClientTTL == 0 {
		c.ClientTTL = 90 * 24 * time.Hour
	}
	if c.StateCookieTTL == 0 {
		c.StateCookieTTL = 10 * time.Minute
	}
	if c.PathPrefix == "" {
		c.PathPrefix = "/oauth"
	}
}

func (c *Config) validate() error {
	if c.Issuer == "" {
		return ErrIssuerRequired
	}
	if c.Upstream == nil {
		return ErrUpstreamRequired
	}
	if c.UserResolver == nil {
		return ErrUserResolverRequired
	}
	if c.Storage == nil {
		return ErrStorageRequired
	}
	if c.KeyManager == nil {
		return ErrKeyManagerRequired
	}
	return nil
}
