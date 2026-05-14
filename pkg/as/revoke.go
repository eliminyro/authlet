package as

import (
	"errors"
	"net/http"
)

// handleRevokeImpl implements RFC 7009 token revocation for refresh
// tokens. Access tokens are stateless and expire naturally. Per the spec,
// missing or unknown tokens still return 200 OK (silent success), and
// confidential clients MUST be authenticated.
func (a *AS) handleRevokeImpl(w http.ResponseWriter, r *http.Request) {
	// Cap request body to 1 MiB. Revoke requests are tiny in practice.
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	if err := r.ParseForm(); err != nil {
		if isBodyTooLarge(err) {
			writeOAuthError(w, http.StatusRequestEntityTooLarge, "invalid_request", "request body too large")
			return
		}
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "form parse error")
		return
	}
	// RFC 7009 §2.1: the client must authenticate the same way it would
	// at the token endpoint.
	authedClientID, err := a.authenticateClient(r.Context(), r)
	if err != nil {
		switch {
		case errors.Is(err, errClientAuthRequired):
			w.Header().Set("WWW-Authenticate", `Basic realm="authlet"`)
			writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "client authentication required")
		default:
			writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		}
		return
	}
	token := r.Form.Get("token")
	hint := r.Form.Get("token_type_hint")
	if token == "" {
		w.WriteHeader(http.StatusOK) // RFC 7009: silent success
		return
	}
	if hint == "" || hint == "refresh_token" {
		hash := hashCode(token)
		if rt, err := a.cfg.Storage.RefreshTokens().Get(r.Context(), hash); err == nil {
			// RFC 7009 §2.2: an authenticated client may only revoke
			// tokens that were issued to it. Don't leak existence.
			if rt.ClientID == authedClientID {
				_ = a.cfg.Storage.RefreshTokens().RevokeFamily(r.Context(), rt.FamilyID)
			}
		}
	}
	// Access tokens are stateless; expire naturally.
	w.WriteHeader(http.StatusOK)
}
