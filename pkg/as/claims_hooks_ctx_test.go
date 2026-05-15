package as

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// ctxKey is a private type used to thread a sentinel into request contexts
// so the ctx-aware hooks can prove they received the right ctx.
type ctxKey struct{}

// runTokenExchange seeds an auth code and POSTs /token for the given AS,
// returning the tokenResponse. The optional reqCtx is attached to the
// request via Request.WithContext so ctx-aware hooks can observe it.
func runTokenExchange(t *testing.T, a *AS, reqCtx context.Context, scope string) tokenResponse {
	t.Helper()
	cid := registerTestClient(t, a, "https://claude/cb")
	verifier, challenge := pkcePair(t)
	code := seedAuthCodeWithScope(t, a, cid, "https://claude/cb", "https://rs/api", challenge, scope)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", cid)
	form.Set("code_verifier", verifier)
	form.Set("redirect_uri", "https://claude/cb")
	form.Set("resource", "https://rs/api")

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if reqCtx != nil {
		req = req.WithContext(reqCtx)
	}
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	var resp tokenResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return resp
}

// TestAdditionalClaimsCtx_ReceivesRequestContext asserts the ctx-aware
// AdditionalClaims hook is invoked with the request context, not a
// background or Setup-scoped one.
func TestAdditionalClaimsCtx_ReceivesRequestContext(t *testing.T) {
	a := newTestAS(t)
	var gotCtx context.Context
	a.cfg.AdditionalClaimsCtx = func(ctx context.Context, _, _, _ string) map[string]any {
		gotCtx = ctx
		return map[string]any{"hello": "world"}
	}

	reqCtx := context.WithValue(context.Background(), ctxKey{}, "sentinel")
	runTokenExchange(t, a, reqCtx, "")
	if gotCtx == nil {
		t.Fatal("AdditionalClaimsCtx was not invoked")
	}
	if v, _ := gotCtx.Value(ctxKey{}).(string); v != "sentinel" {
		t.Fatalf("ctx did not carry request sentinel; got value %q", v)
	}
}

// TestAdditionalClaimsCtx_WinsOverNonCtx asserts that when both AdditionalClaims
// and AdditionalClaimsCtx are set, only the ctx-aware variant fires.
func TestAdditionalClaimsCtx_WinsOverNonCtx(t *testing.T) {
	a := newTestAS(t)
	ctxCalled := false
	nonCtxCalled := false
	a.cfg.AdditionalClaimsCtx = func(context.Context, string, string, string) map[string]any {
		ctxCalled = true
		return nil
	}
	a.cfg.AdditionalClaims = func(string, string, string) map[string]any {
		nonCtxCalled = true
		return nil
	}
	runTokenExchange(t, a, nil, "")
	if !ctxCalled {
		t.Fatal("ctx-aware hook should have been called")
	}
	if nonCtxCalled {
		t.Fatal("non-ctx hook should not have been called when ctx variant is set")
	}
}

// TestAdditionalClaims_NonCtxStillInvokedWhenCtxNil asserts existing
// callers that only set AdditionalClaims continue to work unchanged.
func TestAdditionalClaims_NonCtxStillInvokedWhenCtxNil(t *testing.T) {
	a := newTestAS(t)
	called := false
	a.cfg.AdditionalClaims = func(string, string, string) map[string]any {
		called = true
		return nil
	}
	runTokenExchange(t, a, nil, "")
	if !called {
		t.Fatal("non-ctx hook should be called when ctx variant is nil")
	}
}

// TestIDTokenClaimsCtx_ReceivesRequestContext asserts the ctx-aware
// IDTokenClaims hook is invoked with the request context.
func TestIDTokenClaimsCtx_ReceivesRequestContext(t *testing.T) {
	a := newTestAS(t)
	var gotCtx context.Context
	a.cfg.IDTokenClaimsCtx = func(ctx context.Context, _ string) (string, bool, string, string) {
		gotCtx = ctx
		return "u@example", true, "", ""
	}

	reqCtx := context.WithValue(context.Background(), ctxKey{}, "id-sentinel")
	runTokenExchange(t, a, reqCtx, "openid")
	if gotCtx == nil {
		t.Fatal("IDTokenClaimsCtx was not invoked")
	}
	if v, _ := gotCtx.Value(ctxKey{}).(string); v != "id-sentinel" {
		t.Fatalf("ctx did not carry request sentinel; got value %q", v)
	}
}

// TestIDTokenClaimsCtx_WinsOverNonCtx asserts that when both
// IDTokenClaims and IDTokenClaimsCtx are set, only the ctx-aware
// variant fires.
func TestIDTokenClaimsCtx_WinsOverNonCtx(t *testing.T) {
	a := newTestAS(t)
	ctxCalled := false
	nonCtxCalled := false
	a.cfg.IDTokenClaimsCtx = func(context.Context, string) (string, bool, string, string) {
		ctxCalled = true
		return "", false, "", ""
	}
	a.cfg.IDTokenClaims = func(string) (string, bool, string, string) {
		nonCtxCalled = true
		return "", false, "", ""
	}
	runTokenExchange(t, a, nil, "openid")
	if !ctxCalled {
		t.Fatal("ctx-aware id-token hook should have been called")
	}
	if nonCtxCalled {
		t.Fatal("non-ctx id-token hook should not have been called when ctx variant is set")
	}
}
