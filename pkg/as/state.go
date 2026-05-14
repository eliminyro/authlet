package as

import (
	"net/http"
	"time"
)

const stateCookieName = "authlet_state"

// setStateCookie writes the authlet_state cookie carrying the state key
// that ties the upstream IdP redirect back to the original /authorize
// request.
func (a *AS) setStateCookie(w http.ResponseWriter, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     stateCookieName,
		Value:    value,
		Path:     a.cfg.PathPrefix,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(a.cfg.StateCookieTTL),
	})
}

// readStateCookie returns the value of the authlet_state cookie and ok=true
// if present and non-empty.
func (a *AS) readStateCookie(r *http.Request) (string, bool) {
	c, err := r.Cookie(stateCookieName)
	if err != nil {
		return "", false
	}
	return c.Value, c.Value != ""
}
