package as

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/eliminyro/authlet/pkg/storage"
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
	clientNonce := q.Get("nonce")

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
		// Distinguish "client not in the table" (legitimate 400) from
		// a backend storage failure (operator-visible 500). The
		// previous code conflated both as invalid_client, which masked
		// outages as a client misconfiguration.
		if errors.Is(err, storage.ErrNotFound) {
			writeOAuthError(w, http.StatusBadRequest, "invalid_client", "unknown client")
			return
		}
		a.cfg.Logger.Error("authorize: client lookup failed", "err", err, "client_id", clientID)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "client lookup failed")
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
	// RFC 8707 §2: resource indicators MUST be absolute URIs and
	// SHOULD use HTTPS. We allow http:// only for localhost to keep
	// local development frictionless.
	if ru, err := url.Parse(resource); err != nil || !ru.IsAbs() || ru.Scheme == "" {
		redirectError(w, r, redirect, clientState, "invalid_target", "resource must be an absolute URI")
		return
	} else if ru.Scheme != "https" && !isLocalhost(ru.Host) {
		redirectError(w, r, redirect, clientState, "invalid_target", "resource must use https (or http for localhost dev)")
		return
	}

	stateKey, err := newStateKey()
	if err != nil {
		a.cfg.Logger.Error("authorize: state key gen failed", "err", err, "client_id", clientID)
		redirectError(w, r, redirect, clientState, "server_error", "state gen failed")
		return
	}
	// Per-flow secrets for the UPSTREAM login leg. randomID(32) yields a
	// 43-char base64url string — a valid RFC 7636 code_verifier (charset
	// is a subset of the PKCE unreserved set, length == the 43 minimum).
	upstreamNonce, err := randomID(24)
	if err != nil {
		a.cfg.Logger.Error("authorize: nonce gen failed", "err", err, "client_id", clientID)
		redirectError(w, r, redirect, clientState, "server_error", "nonce gen failed")
		return
	}
	upstreamVerifier, err := randomID(32)
	if err != nil {
		a.cfg.Logger.Error("authorize: verifier gen failed", "err", err, "client_id", clientID)
		redirectError(w, r, redirect, clientState, "server_error", "verifier gen failed")
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
		Nonce:               clientNonce,
		UpstreamNonce:       upstreamNonce,
		UpstreamVerifier:    upstreamVerifier,
		ExpiresAt:           time.Now().Add(a.cfg.StateCookieTTL),
	})
	a.setStateCookie(w, stateKey)
	http.Redirect(w, r, a.cfg.Upstream.AuthURL(stateKey, upstreamNonce, upstreamVerifier), http.StatusFound)
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

// isLocalhost reports whether host (which may include :port) refers to
// the loopback. Used to grant the http://... exception for local
// development while still requiring https for public hosts.
//
// It parses the host as an IP and defers to net.IP.IsLoopback (covering
// 127.0.0.0/8 and ::1) plus the literal "localhost". A non-parseable host
// such as "127.evil.com" is NOT loopback, closing the over-match where
// HasPrefix(host, "127.") accepted attacker-controlled public hosts
// (findings #5/#7).
func isLocalhost(host string) bool {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		h = host
	}
	// A bare bracketed IPv6 literal without a port (e.g. "[::1]") survives
	// SplitHostPort with its brackets intact; strip them before parsing.
	h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// redirectAllowed reports whether the candidate redirect_uri byte-exactly
// matches one of the client's registered redirect URIs, per RFC 9700
// §4.1.1. No case-folding and no query/fragment normalization: the
// presented string must appear verbatim in the client's registration.
func redirectAllowed(allowed []string, candidate string) bool {
	return slices.Contains(allowed, candidate)
}
