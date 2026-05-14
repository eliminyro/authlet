package rs

import (
	"context"
	"crypto/rsa"
	"net/http"
	"strings"

	"github.com/eliminyro/authlet/pkg/jwt"
)

// Config configures bearer validation. JWKS is required; the other fields
// narrow what tokens are accepted and shape the 401 challenge response.
type Config struct {
	// ExpectedIssuer is the iss value tokens must carry. Empty disables the
	// issuer check.
	ExpectedIssuer string
	// ExpectedAudience is the aud value tokens must carry. Empty disables
	// the audience check.
	ExpectedAudience string
	// JWKS resolves token kids to RSA public keys.
	JWKS *JWKSClient
	// ResourceMetadata is the absolute URL of this resource's Protected
	// Resource Metadata document (RFC 9728). When set it is embedded in the
	// WWW-Authenticate challenge so clients can discover the AS.
	ResourceMetadata string
}

// ContextKey is the value type used to stash validated claims on the
// request context. Use FromContext to retrieve them in protected handlers.
type ContextKey struct{}

// FromContext retrieves the claims attached by Middleware. The second
// return value is false when no claims were stored (e.g. the request
// bypassed the middleware).
func FromContext(ctx context.Context) (jwt.Claims, bool) {
	c, ok := ctx.Value(ContextKey{}).(jwt.Claims)
	return c, ok
}

// Middleware wraps next with bearer-token validation. On success it
// invokes next with the parsed claims placed on the request context under
// ContextKey{}. On any failure it writes a 401 with an RFC 9728-style
// WWW-Authenticate challenge and does not call next.
func Middleware(cfg Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tok, ok := extractBearer(r.Header.Get("Authorization"))
			if !ok {
				challenge(w, cfg, "")
				return
			}
			resolve := func(kid string) (*rsa.PublicKey, error) {
				return cfg.JWKS.Key(r.Context(), kid)
			}
			claims, err := jwt.Verify(tok, resolve, jwt.VerifyOptions{
				ExpectedIssuer:   cfg.ExpectedIssuer,
				ExpectedAudience: cfg.ExpectedAudience,
			})
			if err != nil {
				challenge(w, cfg, "invalid_token")
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ContextKey{}, claims)))
		})
	}
}

// extractBearer pulls the token out of an Authorization header value,
// returning false if the header is absent, malformed, or has an empty
// token segment.
func extractBearer(h string) (string, bool) {
	if !strings.HasPrefix(h, "Bearer ") {
		return "", false
	}
	t := strings.TrimPrefix(h, "Bearer ")
	if t == "" {
		return "", false
	}
	return t, true
}

// challenge writes a 401 with a WWW-Authenticate header. When cfg has a
// ResourceMetadata URL it is included so clients can fetch the PRM. When
// errCode is non-empty it is surfaced as the RFC 6750 error parameter.
func challenge(w http.ResponseWriter, cfg Config, errCode string) {
	v := `Bearer realm="authlet"`
	if cfg.ResourceMetadata != "" {
		v += `, resource_metadata="` + cfg.ResourceMetadata + `"`
	}
	if errCode != "" {
		v += `, error="` + errCode + `"`
	}
	w.Header().Set("WWW-Authenticate", v)
	w.WriteHeader(http.StatusUnauthorized)
}
