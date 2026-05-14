package as

import "net/http"

// handleRevokeImpl implements RFC 7009 token revocation for refresh
// tokens. Access tokens are stateless and expire naturally. Per the spec,
// missing or unknown tokens still return 200 OK (silent success).
func (a *AS) handleRevokeImpl(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "form parse error")
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
			_ = a.cfg.Storage.RefreshTokens().RevokeFamily(r.Context(), rt.FamilyID)
		}
	}
	// Access tokens are stateless; expire naturally.
	w.WriteHeader(http.StatusOK)
}
