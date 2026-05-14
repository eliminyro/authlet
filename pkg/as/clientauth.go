package as

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"github.com/eliminyro/authlet/pkg/storage"
	"golang.org/x/crypto/bcrypt"
)

var (
	errClientAuthRequired = errors.New("client_authentication_required")
	errClientAuthFailed   = errors.New("client_authentication_failed")
	// errClientLookupFailed is returned by authenticateClient when
	// Clients.Get returns a non-ErrNotFound error (i.e. a backend
	// storage failure). Callers map this to a 500 server_error instead
	// of the misleading 401 invalid_client.
	errClientLookupFailed = errors.New("client_lookup_failed")
)

// authenticateClient resolves the request to a registered Client. For
// public clients (none auth method), the body's client_id is used and no
// secret check happens. For confidential clients, HTTP Basic Auth is
// required and the bcrypt'd secret must match.
//
// Returns the resolved client_id on success.
func (a *AS) authenticateClient(ctx context.Context, r *http.Request) (string, error) {
	basicID, basicSecret, hasBasic := r.BasicAuth()
	if hasBasic {
		// RFC 6749 §2.3.1: the client_id and client_secret in the
		// Authorization header are application/x-www-form-urlencoded
		// before base64-encoding. Decode after the base64 step.
		decodedID, err := url.QueryUnescape(basicID)
		if err != nil {
			return "", errClientAuthFailed
		}
		decodedSecret, err := url.QueryUnescape(basicSecret)
		if err != nil {
			return "", errClientAuthFailed
		}
		basicID = decodedID
		basicSecret = decodedSecret
	}
	bodyID := r.Form.Get("client_id")

	clientID := basicID
	if clientID == "" {
		clientID = bodyID
	}
	if clientID == "" {
		return "", errClientAuthRequired
	}
	if basicID != "" && bodyID != "" && basicID != bodyID {
		return "", errClientAuthFailed
	}

	cl, err := a.cfg.Storage.Clients().Get(ctx, clientID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return "", errClientAuthFailed
		}
		a.cfg.Logger.Error("clientauth: storage lookup failed", "err", err, "client_id", clientID)
		return "", errClientLookupFailed
	}

	switch cl.TokenEndpointAuthMethod {
	case "", "none":
		return cl.ClientID, nil
	case "client_secret_basic":
		if !hasBasic {
			return "", errClientAuthRequired
		}
		if len(cl.SecretHash) == 0 {
			return "", errClientAuthFailed
		}
		if err := bcrypt.CompareHashAndPassword(cl.SecretHash, []byte(basicSecret)); err != nil {
			return "", errClientAuthFailed
		}
		return cl.ClientID, nil
	default:
		return "", errClientAuthFailed
	}
}
