package as

import (
	"bytes"
	"context"
	"crypto/rand"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eliminyro/authlet/pkg/idp"
	"github.com/eliminyro/authlet/pkg/jwt"
	"github.com/eliminyro/authlet/pkg/storage/memstore"
)

// TestConfig_DefaultLoggerIsSlogDefault verifies that when Config.Logger
// is unset, defaults() wires it to slog.Default so handlers never panic
// on a nil logger.
func TestConfig_DefaultLoggerIsSlogDefault(t *testing.T) {
	a := newTestAS(t)
	if a.cfg.Logger == nil {
		t.Fatal("expected Logger to be set to slog.Default, got nil")
	}
	if a.cfg.Logger != slog.Default() {
		// We compare by pointer identity because defaults() assigns
		// slog.Default() directly.
		t.Fatalf("expected Logger == slog.Default()")
	}
}

// newTestASWithLogger constructs an AS whose Logger writes to the given
// buffer at DEBUG level — used by tests that assert specific log events
// are emitted.
func newTestASWithLogger(t *testing.T, buf *bytes.Buffer) *AS {
	t.Helper()
	mk := make([]byte, 32)
	_, _ = rand.Read(mk)
	store := memstore.New()
	mgr := jwt.NewManager(store.SigningKeys(), mk)
	_ = mgr.Bootstrap(context.Background())
	logger := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	a, err := New(Config{
		Issuer:       "https://example.test",
		PathPrefix:   "/oauth",
		Upstream:     idp.NewForTest("https://upstream.test"),
		UserResolver: idp.UserResolverFunc(func(context.Context, idp.Claims) (string, error) { return "u", nil }),
		Storage:      store,
		KeyManager:   mgr,
		Logger:       logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// TestConfig_LoggerCaptures500SiteErrors verifies that the configured
// Logger receives an entry when a 500-class error path fires (here:
// register storage failure via an ErrAlreadyExists race simulated by
// creating the same client twice — actually use register success and
// then bad path). We assert at least one log line is emitted for a
// deliberately broken claims hook panic.
func TestConfig_LoggerCaptures500SiteErrors(t *testing.T) {
	buf := &bytes.Buffer{}
	a := newTestASWithLogger(t, buf)
	a.cfg.AdditionalClaims = func(userID, clientID, resource string) map[string]any {
		panic("deliberate test panic")
	}
	cid := registerTestClient(t, a, "https://claude/cb")
	verifier, challenge := pkcePair(t)
	code := seedAuthCode(t, a, cid, "https://claude/cb", "https://rs/api", challenge)

	form := "grant_type=authorization_code" +
		"&code=" + code +
		"&client_id=" + cid +
		"&code_verifier=" + verifier +
		"&redirect_uri=https%3A%2F%2Fclaude%2Fcb" +
		"&resource=https%3A%2F%2Frs%2Fapi"
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (panic recovered), got %d body=%s", w.Code, w.Body.String())
	}
	out := buf.String()
	if !strings.Contains(out, "AdditionalClaims hook panicked") {
		t.Fatalf("expected logger to record panic recovery, got: %q", out)
	}
}
