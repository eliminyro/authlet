package as

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestCallback_MissingStateOrCode(t *testing.T) {
	a := newTestAS(t)
	req := httptest.NewRequest(http.MethodGet, "/idp/callback?state=&code=", nil)
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status %d", w.Code)
	}
}

func TestCallback_StateCookieMismatch(t *testing.T) {
	a := newTestAS(t)
	req := httptest.NewRequest(http.MethodGet, "/idp/callback?state=abc&code=xyz", nil)
	req.AddCookie(&http.Cookie{Name: stateCookieName, Value: "different"})
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status %d", w.Code)
	}
}

func TestCallback_UnknownState(t *testing.T) {
	a := newTestAS(t)
	req := httptest.NewRequest(http.MethodGet, "/idp/callback?state=abc&code=xyz", nil)
	req.AddCookie(&http.Cookie{Name: stateCookieName, Value: "abc"})
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status %d", w.Code)
	}
}

// TestCallback_ForwardsUpstreamError asserts that an upstream OAuth error
// (e.g. access_denied) is forwarded to the client's redirect_uri rather
// than producing a 400.
func TestCallback_ForwardsUpstreamError(t *testing.T) {
	a := newTestAS(t)
	stateKey, _ := newStateKey()
	a.states.Put(stateKey, pendingAuth{
		ClientID:    "cid",
		RedirectURI: "https://claude/cb",
		State:       "client-state-xyz",
		ExpiresAt:   time.Now().Add(time.Minute),
	})
	req := httptest.NewRequest(http.MethodGet,
		"/idp/callback?state="+stateKey+"&error=access_denied&error_description=user+denied", nil)
	req.AddCookie(&http.Cookie{Name: stateCookieName, Value: stateKey})
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d body=%s", w.Code, w.Body.String())
	}
	loc := w.Header().Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("bad redirect: %v", err)
	}
	if u.Host != "claude" {
		t.Fatalf("wrong redirect host: %q", loc)
	}
	q := u.Query()
	if q.Get("error") != "access_denied" {
		t.Fatalf("error not forwarded: %q", loc)
	}
	if q.Get("state") != "client-state-xyz" {
		t.Fatalf("client state not preserved: %q", loc)
	}
}
