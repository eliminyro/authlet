package as

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/eliminyro/authlet/pkg/storage"
)

// failingClientGetStore is a ClientStore whose Get returns a backend
// error (not storage.ErrNotFound). Used to assert that handlers route
// such errors to 500 instead of conflating them with invalid_client.
type failingClientGetStore struct {
	storage.ClientStore
}

var errSimulatedBackend = errors.New("simulated backend failure")

func (f failingClientGetStore) Get(ctx context.Context, clientID string) (*storage.Client, error) {
	return nil, errSimulatedBackend
}

// stubStorageWithClient swaps in a custom client store while delegating
// the rest to an inner storage.
type stubStorageWithClient struct {
	inner   storage.Storage
	clients storage.ClientStore
}

func (s *stubStorageWithClient) Clients() storage.ClientStore { return s.clients }
func (s *stubStorageWithClient) Codes() storage.CodeStore     { return s.inner.Codes() }
func (s *stubStorageWithClient) RefreshTokens() storage.RefreshTokenStore {
	return s.inner.RefreshTokens()
}
func (s *stubStorageWithClient) SigningKeys() storage.SigningKeyStore { return s.inner.SigningKeys() }

// TestAuthorize_StorageErrorIsServerError asserts that when the client
// store returns a non-ErrNotFound error during /authorize, the response
// is 500 server_error — NOT 400 invalid_client — so operators see the
// backend failure clearly.
func TestAuthorize_StorageErrorIsServerError(t *testing.T) {
	a := newTestAS(t)
	a.cfg.Storage = &stubStorageWithClient{
		inner:   a.cfg.Storage,
		clients: failingClientGetStore{ClientStore: a.cfg.Storage.Clients()},
	}
	u := "/authorize?response_type=code&client_id=x&redirect_uri=https://claude/cb&code_challenge=abc&code_challenge_method=S256&resource=https://rs/api"
	req := httptest.NewRequest(http.MethodGet, u, nil)
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 for backend storage error, got %d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "server_error") {
		t.Fatalf("expected server_error code in body, got %s", w.Body.String())
	}
}

// TestToken_ClientStorageErrorIsServerError asserts the /token endpoint
// returns 500 (not 401) when the client store returns a backend error
// during authentication. This ensures storage outages don't masquerade
// as client auth failures.
func TestToken_ClientStorageErrorIsServerError(t *testing.T) {
	a := newTestAS(t)
	a.cfg.Storage = &stubStorageWithClient{
		inner:   a.cfg.Storage,
		clients: failingClientGetStore{ClientStore: a.cfg.Storage.Clients()},
	}
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("client_id", "any-client")
	form.Set("refresh_token", "irrelevant")
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 for backend storage error, got %d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "server_error") {
		t.Fatalf("expected server_error code in body, got %s", w.Body.String())
	}
}
