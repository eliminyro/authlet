package as

import (
	"context"
	"errors"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

var (
	errClientAuthRequired = errors.New("client_authentication_required")
	errClientAuthFailed   = errors.New("client_authentication_failed")
)

// authenticateClient resolves the request to a registered Client. For
// public clients (none auth method), the body's client_id is used and no
// secret check happens. For confidential clients, HTTP Basic Auth is
// required and the bcrypt'd secret must match.
//
// Returns the resolved client_id on success.
func (a *AS) authenticateClient(ctx context.Context, r *http.Request) (string, error) {
	basicID, basicSecret, hasBasic := r.BasicAuth()
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
		return "", errClientAuthFailed
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
