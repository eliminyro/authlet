package mcp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPRMHandler_ShapeAndCacheHeader(t *testing.T) {
	p := PRM{
		Resource:               "https://hilo.example/api/mcp",
		AuthorizationServers:   []string{"https://hilo.example"},
		BearerMethodsSupported: []string{"header"},
		ScopesSupported:        []string{"mcp"},
	}
	h := PRMHandler(p)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource/api/mcp", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type %q", ct)
	}
	if cc := w.Header().Get("Cache-Control"); cc == "" {
		t.Fatal("missing cache-control")
	}
	var got PRM
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if got.Resource != p.Resource || len(got.AuthorizationServers) != 1 {
		t.Fatalf("shape mismatch: %+v", got)
	}
}
