package as

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"time"

	"github.com/eliminyro/authlet/pkg/storage"
)

// handleIDPCallbackImpl finishes the upstream OIDC login: it validates the
// state cookie + query, exchanges the upstream code for claims, resolves
// the internal user, mints a one-time authorization code, and 302s back to
// the client's redirect_uri with code + original state. Upstream OAuth
// errors (e.g. ?error=access_denied) are forwarded to the client.
func (a *AS) handleIDPCallbackImpl(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	stateKey := q.Get("state")
	upstreamCode := q.Get("code")
	upstreamErr := q.Get("error")
	if stateKey == "" {
		http.Error(w, "missing state", http.StatusBadRequest)
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

	// Forward upstream OAuth errors to the client per RFC 6749 §4.1.2.1.
	if upstreamErr != "" {
		redirectError(w, r, pending.RedirectURI, pending.State, upstreamErr, q.Get("error_description"))
		return
	}
	if upstreamCode == "" {
		http.Error(w, "missing code", http.StatusBadRequest)
		return
	}

	claims, err := a.cfg.Upstream.Exchange(r.Context(), upstreamCode)
	if err != nil {
		a.cfg.Logger.Error("callback: upstream exchange failed", "err", err, "client_id", pending.ClientID)
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
		a.cfg.Logger.Error("callback: code gen failed", "err", err, "client_id", pending.ClientID)
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
		a.cfg.Logger.Error("callback: code save failed", "err", err, "client_id", pending.ClientID)
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
