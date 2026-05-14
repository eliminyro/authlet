package as

import (
	"context"
	"crypto/rand"
	"testing"

	"github.com/eliminyro/authlet/pkg/idp"
	"github.com/eliminyro/authlet/pkg/jwt"
	"github.com/eliminyro/authlet/pkg/storage/memstore"
)

func newTestAS(t *testing.T) *AS {
	t.Helper()
	mk := make([]byte, 32)
	_, _ = rand.Read(mk)
	store := memstore.New()
	mgr := jwt.NewManager(store.SigningKeys(), mk)
	_ = mgr.Bootstrap(context.Background())
	a, err := New(Config{
		Issuer:       "https://example.test",
		PathPrefix:   "/oauth",
		Upstream:     idp.NewForTest("https://upstream.test"),
		UserResolver: idp.UserResolverFunc(func(context.Context, idp.Claims) (string, error) { return "u", nil }),
		Storage:      store,
		KeyManager:   mgr,
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestNew_RequiresIssuer(t *testing.T) {
	_, err := New(Config{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestNew_RejectsTrailingSlashIssuer(t *testing.T) {
	_, err := New(Config{Issuer: "https://example.test/"})
	if err == nil {
		t.Fatal("expected error for trailing-slash Issuer")
	}
}

func TestNew_RejectsTrailingSlashPathPrefix(t *testing.T) {
	_, err := New(Config{Issuer: "https://example.test", PathPrefix: "/oauth/"})
	if err == nil {
		t.Fatal("expected error for trailing-slash PathPrefix")
	}
}

func TestNew_RejectsPathPrefixWithoutLeadingSlash(t *testing.T) {
	_, err := New(Config{Issuer: "https://example.test", PathPrefix: "oauth"})
	if err == nil {
		t.Fatal("expected error for PathPrefix without leading slash")
	}
}

// TestNew_RejectsZeroOIDCProvider asserts that a non-nil but
// uninitialised *idp.OIDCProvider (i.e. &idp.OIDCProvider{}) is rejected
// because Configured() returns false.
func TestNew_RejectsZeroOIDCProvider(t *testing.T) {
	_, err := New(Config{
		Issuer:   "https://example.test",
		Upstream: &idp.OIDCProvider{},
	})
	if err == nil {
		t.Fatal("expected error for zero-valued *OIDCProvider")
	}
}
