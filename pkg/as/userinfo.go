package as

import (
	"net/http"
	"strings"

	"github.com/eliminyro/authlet/pkg/jwt"
)

// handleUserinfoImpl serves the OIDC /userinfo endpoint: it verifies the
// Bearer access token's signature and issuer, then returns sub + any extra
// claims as JSON.
func (a *AS) handleUserinfoImpl(w http.ResponseWriter, r *http.Request) {
	authz := r.Header.Get("Authorization")
	if !strings.HasPrefix(authz, "Bearer ") {
		w.Header().Set("WWW-Authenticate", `Bearer realm="authlet"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	tok := strings.TrimPrefix(authz, "Bearer ")
	claims, err := jwt.Verify(tok, a.cfg.KeyManager.PublicKeyFunc(r.Context()), jwt.VerifyOptions{
		ExpectedIssuer: a.cfg.Issuer,
	})
	if err != nil {
		// RFC 6750 §3: invalid token must carry WWW-Authenticate with
		// error="invalid_token".
		w.Header().Set("WWW-Authenticate", `Bearer realm="authlet", error="invalid_token"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	out := map[string]any{"sub": claims.Subject}
	for k, v := range claims.Extra {
		out[k] = v
	}
	writeJSON(w, http.StatusOK, out)
}
