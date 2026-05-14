package as

import (
	"context"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
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
		Upstream:     &idp.OIDCProvider{},
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

func TestHandler_StubsReturn501(t *testing.T) {
	a := newTestAS(t)
	h := a.Handler()
	for _, path := range []string{"/authorize", "/idp/callback", "/userinfo"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusNotImplemented {
			t.Fatalf("%s: got %d want 501", path, w.Code)
		}
	}
}
