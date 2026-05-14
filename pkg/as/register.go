package as

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/eliminyro/authlet/pkg/storage"
)

type dcrRequest struct {
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
}

type dcrResponse struct {
	ClientID                string   `json:"client_id"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	ClientName              string   `json:"client_name,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
}

var errInvalidRedirect = errors.New("invalid redirect_uris")

func (a *AS) handleRegisterImpl(w http.ResponseWriter, r *http.Request) {
	var req dcrRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "malformed JSON")
		return
	}
	if len(req.RedirectURIs) == 0 {
		writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", errInvalidRedirect.Error())
		return
	}
	for _, u := range req.RedirectURIs {
		if u == "" {
			writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", errInvalidRedirect.Error())
			return
		}
		// RFC 7591 §2.3.1 / RFC 6749 §3.1.2: redirect_uris MUST be
		// absolute URIs and MUST NOT contain a fragment component.
		parsed, err := url.Parse(u)
		if err != nil || !parsed.IsAbs() || parsed.Fragment != "" {
			writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", errInvalidRedirect.Error())
			return
		}
	}
	clientID, err := randomID(16)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "id generation failed")
		return
	}
	now := time.Now().UTC()
	// DCR'd clients are always public — no client_secret issued.
	// Confidential clients must be pre-registered out-of-band (e.g. SQL insert).
	cl := storage.Client{
		ClientID:                clientID,
		TokenEndpointAuthMethod: "none",
		RedirectURIs:            req.RedirectURIs,
		Metadata: map[string]any{
			"client_name":    req.ClientName,
			"grant_types":    grantTypesOrDefault(req.GrantTypes),
			"response_types": responseTypesOrDefault(req.ResponseTypes),
			"scope":          scopeOrDefault(req.Scope),
		},
		CreatedAt:  now,
		LastUsedAt: now,
		ExpiresAt:  now.Add(a.cfg.ClientTTL),
	}
	if err := a.cfg.Storage.Clients().Create(r.Context(), cl); err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "storage failed")
		return
	}
	writeJSON(w, http.StatusCreated, dcrResponse{
		ClientID:                clientID,
		ClientIDIssuedAt:        now.Unix(),
		RedirectURIs:            cl.RedirectURIs,
		GrantTypes:              grantTypesOrDefault(req.GrantTypes),
		ResponseTypes:           responseTypesOrDefault(req.ResponseTypes),
		TokenEndpointAuthMethod: authMethodOrDefault(req.TokenEndpointAuthMethod),
		ClientName:              req.ClientName,
		Scope:                   scopeOrDefault(req.Scope),
	})
}

func grantTypesOrDefault(g []string) []string {
	if len(g) == 0 {
		return []string{"authorization_code", "refresh_token"}
	}
	return g
}

func responseTypesOrDefault(g []string) []string {
	if len(g) == 0 {
		return []string{"code"}
	}
	return g
}

func authMethodOrDefault(m string) string {
	if m == "" {
		return "none"
	}
	return m
}

func scopeOrDefault(s string) string {
	if s == "" {
		return "mcp"
	}
	return s
}

func randomID(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// writeOAuthError emits the standard OAuth 2.0 error response shape.
func writeOAuthError(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}
