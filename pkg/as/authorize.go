package as

import (
	"net/http"
	"net/url"
	"strings"
	"time"
)

// handleAuthorizeImpl validates the /authorize request, stashes a
// pendingAuth in the state store, sets the state cookie, and 302s the
// user-agent to the upstream IdP.
func (a *AS) handleAuthorizeImpl(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	respType := q.Get("response_type")
	clientID := q.Get("client_id")
	redirect := q.Get("redirect_uri")
	scope := q.Get("scope")
	resource := q.Get("resource")
	clientState := q.Get("state")
	challenge := q.Get("code_challenge")
	challengeMethod := q.Get("code_challenge_method")

	if respType != "code" {
		writeOAuthError(w, http.StatusBadRequest, "unsupported_response_type", "response_type must be code")
		return
	}
	if clientID == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "client_id required")
		return
	}
	if redirect == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "redirect_uri required")
		return
	}
	if challenge == "" || challengeMethod != "S256" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "PKCE S256 required")
		return
	}
	if resource == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_target", "resource indicator required")
		return
	}

	client, err := a.cfg.Storage.Clients().Get(r.Context(), clientID)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client", "unknown client")
		return
	}
	if !redirectAllowed(client.RedirectURIs, redirect) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "redirect_uri not registered")
		return
	}

	stateKey, err := newStateKey()
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "state gen failed")
		return
	}
	a.states.Put(stateKey, pendingAuth{
		ClientID:            clientID,
		RedirectURI:         redirect,
		Scope:               scope,
		Resource:            resource,
		State:               clientState,
		CodeChallenge:       challenge,
		CodeChallengeMethod: challengeMethod,
		ExpiresAt:           time.Now().Add(a.cfg.StateCookieTTL),
	})
	a.setStateCookie(w, stateKey)
	http.Redirect(w, r, a.cfg.Upstream.AuthURL(stateKey), http.StatusFound)
}

// redirectAllowed reports whether the candidate redirect_uri matches one of
// the client's registered redirect URIs. Comparison is case-insensitive for
// the exact match path, with a fallback to scheme/host/path equality.
func redirectAllowed(allowed []string, candidate string) bool {
	c, err := url.Parse(candidate)
	if err != nil {
		return false
	}
	for _, u := range allowed {
		if strings.EqualFold(u, candidate) {
			return true
		}
		// Allow exact host match for localhost public clients.
		pu, err := url.Parse(u)
		if err == nil && pu.Host == c.Host && pu.Path == c.Path && pu.Scheme == c.Scheme {
			return true
		}
	}
	return false
}
