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
//
// Errors raised BEFORE the redirect_uri is validated are returned as JSON
// (we cannot trust the redirect_uri yet). Errors raised AFTER the
// redirect_uri is validated are reported via redirect to the registered
// redirect_uri with error/error_description/state query params, per
// OAuth 2.1 §4.1.2.1.
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

	// Pre-redirect-validation errors: cannot trust redirect_uri, so we
	// return a JSON body. Per RFC 6749 §4.1.2.1.
	if clientID == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "client_id required")
		return
	}
	if redirect == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "redirect_uri required")
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

	// Post-redirect-validation errors: redirect back to client with the
	// error in the query string.
	if respType != "code" {
		redirectError(w, r, redirect, clientState, "unsupported_response_type", "response_type must be code")
		return
	}
	if challenge == "" || challengeMethod != "S256" {
		redirectError(w, r, redirect, clientState, "invalid_request", "PKCE S256 required")
		return
	}
	if resource == "" {
		redirectError(w, r, redirect, clientState, "invalid_target", "resource indicator required")
		return
	}

	stateKey, err := newStateKey()
	if err != nil {
		a.cfg.Logger.Error("authorize: state key gen failed", "err", err, "client_id", clientID)
		redirectError(w, r, redirect, clientState, "server_error", "state gen failed")
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

// redirectError sends a 302 to the client's redirect_uri with OAuth error
// query parameters. Use only for errors raised AFTER the redirect_uri has
// been validated against the client's registration.
func redirectError(w http.ResponseWriter, r *http.Request, redirectURI, state, errCode, errDesc string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		// Should not happen — redirectURI was validated upstream — but
		// fall back to a JSON error rather than disclosing nothing.
		writeOAuthError(w, http.StatusBadRequest, errCode, errDesc)
		return
	}
	qs := u.Query()
	qs.Set("error", errCode)
	if errDesc != "" {
		qs.Set("error_description", errDesc)
	}
	if state != "" {
		qs.Set("state", state)
	}
	u.RawQuery = qs.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
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
