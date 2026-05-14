package as

import (
	"net/http"
	"net/http/httptest"
	"testing"
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
