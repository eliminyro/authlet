package as

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/url"
	"time"

	"github.com/eliminyro/authlet/pkg/storage"
)

// handleIDPCallbackImpl finishes the upstream OIDC login: it validates the
// state cookie + query, exchanges the upstream code for claims, resolves
// the internal user, mints a one-time authorization code, and 302s back to
// the client's redirect_uri with code + original state.
func (a *AS) handleIDPCallbackImpl(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	stateKey := q.Get("state")
	upstreamCode := q.Get("code")
	if stateKey == "" || upstreamCode == "" {
		http.Error(w, "missing state or code", http.StatusBadRequest)
		return
	}
	cookieState, ok := a.readStateCookie(r)
	if !ok || cookieState != stateKey {
		http.Error(w, "state mismatch", http.StatusBadRequest)
		return
	}
	pending, ok := a.states.Consume(stateKey)
	if !ok {
		http.Error(w, "state expired or unknown", http.StatusBadRequest)
		return
	}

	claims, err := a.cfg.Upstream.Exchange(r.Context(), upstreamCode)
	if err != nil {
		http.Error(w, "upstream exchange failed", http.StatusBadGateway)
		return
	}
	userID, err := a.cfg.UserResolver.Resolve(r.Context(), claims)
	if err != nil {
		http.Error(w, "user not authorized", http.StatusForbidden)
		return
	}

	codePlain, err := randomID(32)
	if err != nil {
		http.Error(w, "code gen failed", http.StatusInternalServerError)
		return
	}
	codeHash := hashCode(codePlain)
	expires := time.Now().Add(a.cfg.AuthCodeTTL)
	if err := a.cfg.Storage.Codes().Save(r.Context(), storage.AuthCode{
		CodeHash:      codeHash,
		ClientID:      pending.ClientID,
		UserID:        userID,
		Resource:      pending.Resource,
		Scope:         pending.Scope,
		PKCEChallenge: pending.CodeChallenge,
		PKCEMethod:    pending.CodeChallengeMethod,
		RedirectURI:   pending.RedirectURI,
		ExpiresAt:     expires,
	}); err != nil {
		http.Error(w, "code save failed", http.StatusInternalServerError)
		return
	}

	u, _ := url.Parse(pending.RedirectURI)
	qs := u.Query()
	qs.Set("code", codePlain)
	if pending.State != "" {
		qs.Set("state", pending.State)
	}
	u.RawQuery = qs.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// hashCode returns hex-encoded sha256 of the plaintext. Used for storing
// authorization codes and refresh tokens by hash.
func hashCode(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}

// base64URLNoPad encodes b with base64url and no padding. Reserved for
// PKCE/state encoding helpers.
func base64URLNoPad(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
