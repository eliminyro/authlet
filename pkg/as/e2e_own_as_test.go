package as

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eliminyro/authlet/pkg/idp"
	"github.com/eliminyro/authlet/pkg/jwt"
	"github.com/eliminyro/authlet/pkg/storage/memstore"
	jwtv5 "github.com/golang-jwt/jwt/v5"
)

// fakeUpstreamAS stands in for Google in the own-AS replay-control test.
// Unlike the fake in integration_test.go it records the nonce and PKCE
// challenge it receives on /authorize and echoes the same nonce back in
// the id_token minted at /token, so the AS's upstream nonce binding can be
// exercised end-to-end. tamperNonce flips the echoed nonce to prove the
// AS rejects a mismatch.
type fakeUpstreamAS struct {
	server   *httptest.Server
	key      *rsa.PrivateKey
	kid      string
	clientID string
	email    string

	mu           sync.Mutex
	gotNonce     string
	gotChallenge string
	gotMethod    string
	gotVerifier  string
	tamperNonce  bool
}

func newFakeUpstreamAS(t *testing.T) *fakeUpstreamAS {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	f := &fakeUpstreamAS{key: k, kid: "fk1", clientID: "upstream-client", email: "alice@example.test"}
	mux := http.NewServeMux()
	var issuer string
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": issuer, "authorization_endpoint": issuer + "/authorize",
			"token_endpoint": issuer + "/token", "jwks_uri": issuer + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
		})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		f.mu.Lock()
		f.gotNonce = q.Get("nonce")
		f.gotChallenge = q.Get("code_challenge")
		f.gotMethod = q.Get("code_challenge_method")
		f.mu.Unlock()
		redir, _ := url.Parse(q.Get("redirect_uri"))
		rq := redir.Query()
		rq.Set("code", "upstream-code")
		rq.Set("state", q.Get("state"))
		redir.RawQuery = rq.Encode()
		http.Redirect(w, r, redir.String(), http.StatusFound)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		n := base64.RawURLEncoding.EncodeToString(k.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes())
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": f.kid, "n": n, "e": e}},
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.mu.Lock()
		f.gotVerifier = r.Form.Get("code_verifier")
		nonce := f.gotNonce
		if f.tamperNonce {
			nonce = "tampered-" + nonce
		}
		f.mu.Unlock()
		idTok := jwtv5.NewWithClaims(jwtv5.SigningMethodRS256, jwtv5.MapClaims{
			"iss": issuer, "sub": "google-sub", "aud": f.clientID,
			"email": f.email, "email_verified": true, "nonce": nonce,
			"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
		})
		idTok.Header["kid"] = f.kid
		s, _ := idTok.SignedString(k)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "x", "id_token": s, "token_type": "Bearer", "expires_in": 3600,
		})
	})
	f.server = httptest.NewServer(mux)
	issuer = f.server.URL
	return f
}

// e2eHarness wires a fake upstream + a TLS-mounted AS and returns an HTTP
// client that follows redirects manually so each Location can be inspected.
type e2eHarness struct {
	fake   *fakeUpstreamAS
	asSrv  *httptest.Server
	client *http.Client
	mgr    *jwt.Manager
}

func newE2EHarness(t *testing.T, fake *fakeUpstreamAS) *e2eHarness {
	t.Helper()
	mk := make([]byte, 32)
	if _, err := rand.Read(mk); err != nil {
		t.Fatal(err)
	}
	store := memstore.New()
	mgr := jwt.NewManager(store.SigningKeys(), mk)
	if err := mgr.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}

	// A TLS server is required because the state cookie is Secure and a
	// cookiejar will not replay Secure cookies over plain HTTP.
	mux := http.NewServeMux()
	asSrv := httptest.NewTLSServer(mux)

	upstream, err := idp.NewOIDC(context.Background(), fake.server.URL, fake.clientID, "secret",
		asSrv.URL+"/oauth/idp/callback", []string{"openid", "email"})
	if err != nil {
		t.Fatalf("idp.NewOIDC: %v", err)
	}
	resolver := idp.UserResolverFunc(func(_ context.Context, c idp.Claims) (string, error) {
		return "user-" + c.Email, nil
	})
	server, err := New(Config{
		Issuer:       asSrv.URL,
		PathPrefix:   "/oauth",
		Upstream:     upstream,
		UserResolver: resolver,
		Storage:      store,
		KeyManager:   mgr,
	})
	if err != nil {
		t.Fatal(err)
	}
	mux.Handle("/oauth/", http.StripPrefix("/oauth", server.Handler()))

	jar, _ := cookiejar.New(nil)
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec // test server
	client := &http.Client{
		Jar:       jar,
		Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &e2eHarness{fake: fake, asSrv: asSrv, client: client, mgr: mgr}
}

func (h *e2eHarness) register(t *testing.T) string {
	t.Helper()
	body := `{"redirect_uris":["` + h.asSrv.URL + `/client/cb"]}`
	req, _ := http.NewRequest(http.MethodPost, h.asSrv.URL+"/oauth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatalf("dcr: %v", err)
	}
	defer resp.Body.Close()
	var dcr dcrResponse
	if err := json.NewDecoder(resp.Body).Decode(&dcr); err != nil {
		t.Fatalf("dcr decode: %v", err)
	}
	if dcr.ClientID == "" {
		t.Fatalf("no client_id, status=%d", resp.StatusCode)
	}
	return dcr.ClientID
}

// TestE2E_OwnASReplayControls drives the full authlet AS flow and asserts
// the new controls end-to-end: the upstream leg carries a nonce + S256
// PKCE challenge, the callback redirect carries the RFC 9207 iss param,
// and the minted id_token carries the client nonce plus a correct at_hash.
func TestE2E_OwnASReplayControls(t *testing.T) {
	fake := newFakeUpstreamAS(t)
	defer fake.server.Close()
	h := newE2EHarness(t, fake)
	defer h.asSrv.Close()

	clientID := h.register(t)
	verifier, challenge := pkcePair(t)
	const clientNonce = "client-nonce-xyz"

	// Step 1: /authorize (client PKCE + nonce + openid scope) → 302 upstream.
	authURL := h.asSrv.URL + "/oauth/authorize?response_type=code&client_id=" + clientID +
		"&redirect_uri=" + url.QueryEscape(h.asSrv.URL+"/client/cb") +
		"&resource=" + url.QueryEscape(h.asSrv.URL+"/api/mcp") +
		"&scope=" + url.QueryEscape("openid mcp") +
		"&code_challenge=" + challenge + "&code_challenge_method=S256" +
		"&state=client-state&nonce=" + clientNonce
	r1, err := h.client.Get(authURL)
	if err != nil {
		t.Fatalf("authorize get: %v", err)
	}
	defer r1.Body.Close()
	if r1.StatusCode != http.StatusFound {
		t.Fatalf("authorize status %d body=%s", r1.StatusCode, slurp(r1.Body))
	}
	upstreamURL := r1.Header.Get("Location")

	// Step 2: follow to upstream, which bounces straight back with a code.
	r2, err := h.client.Get(upstreamURL)
	if err != nil {
		t.Fatalf("upstream get: %v", err)
	}
	defer r2.Body.Close()
	if r2.StatusCode != http.StatusFound {
		t.Fatalf("upstream status %d", r2.StatusCode)
	}
	callbackURL := r2.Header.Get("Location")

	// Step 3: follow back to /idp/callback → 302 to client redirect.
	r3, err := h.client.Get(callbackURL)
	if err != nil {
		t.Fatalf("callback get: %v", err)
	}
	defer r3.Body.Close()
	if r3.StatusCode != http.StatusFound {
		t.Fatalf("callback status %d body=%s", r3.StatusCode, slurp(r3.Body))
	}
	clientRedirect, _ := url.Parse(r3.Header.Get("Location"))
	code := clientRedirect.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in client redirect: %s", clientRedirect.String())
	}
	// RFC 9207 iss param present + correct.
	if got := clientRedirect.Query().Get("iss"); got != h.asSrv.URL {
		t.Fatalf("iss param = %q, want %q", got, h.asSrv.URL)
	}
	if got := clientRedirect.Query().Get("state"); got != "client-state" {
		t.Fatalf("state not preserved: %q", got)
	}

	// Upstream leg must have received a nonce + S256 PKCE challenge.
	fake.mu.Lock()
	un, uc, um, uv := fake.gotNonce, fake.gotChallenge, fake.gotMethod, fake.gotVerifier
	fake.mu.Unlock()
	if un == "" {
		t.Fatal("upstream /authorize received no nonce")
	}
	if uc == "" || um != "S256" {
		t.Fatalf("upstream PKCE missing: challenge=%q method=%q", uc, um)
	}
	if uv == "" {
		t.Fatal("upstream /token received no code_verifier")
	}

	// Step 4: exchange code at /token.
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", clientID)
	form.Set("code_verifier", verifier)
	form.Set("redirect_uri", h.asSrv.URL+"/client/cb")
	form.Set("resource", h.asSrv.URL+"/api/mcp")
	tokReq, _ := http.NewRequest(http.MethodPost, h.asSrv.URL+"/oauth/token", strings.NewReader(form.Encode()))
	tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r4, err := h.client.Do(tokReq)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	defer r4.Body.Close()
	if r4.StatusCode != http.StatusOK {
		t.Fatalf("token status %d body=%s", r4.StatusCode, slurp(r4.Body))
	}
	var tok tokenResponse
	if err := json.NewDecoder(r4.Body).Decode(&tok); err != nil {
		t.Fatalf("token decode: %v", err)
	}
	if tok.AccessToken == "" || tok.IDToken == "" {
		t.Fatalf("missing tokens: %+v", tok)
	}

	// id_token must carry the client nonce and a correct at_hash.
	idc, err := jwt.Verify(tok.IDToken, h.mgr.PublicKeyFunc(context.Background()), jwt.VerifyOptions{
		ExpectedIssuer: h.asSrv.URL,
	})
	if err != nil {
		t.Fatalf("verify id_token: %v", err)
	}
	if idc.Extra["nonce"] != clientNonce {
		t.Fatalf("id_token nonce = %v, want %q", idc.Extra["nonce"], clientNonce)
	}
	gotHash, _ := idc.Extra["at_hash"].(string)
	if gotHash == "" {
		t.Fatal("id_token missing at_hash")
	}
	if want := accessTokenHash(tok.AccessToken); gotHash != want {
		t.Fatalf("at_hash = %q, want %q", gotHash, want)
	}
}

// TestE2E_UpstreamNonceMismatchRejected proves the callback fails closed
// when the upstream id_token's nonce does not match the per-flow nonce
// (upstream authorization-code injection defense).
func TestE2E_UpstreamNonceMismatchRejected(t *testing.T) {
	fake := newFakeUpstreamAS(t)
	fake.tamperNonce = true
	defer fake.server.Close()
	h := newE2EHarness(t, fake)
	defer h.asSrv.Close()

	clientID := h.register(t)
	_, challenge := pkcePair(t)

	authURL := h.asSrv.URL + "/oauth/authorize?response_type=code&client_id=" + clientID +
		"&redirect_uri=" + url.QueryEscape(h.asSrv.URL+"/client/cb") +
		"&resource=" + url.QueryEscape(h.asSrv.URL+"/api/mcp") +
		"&scope=" + url.QueryEscape("openid mcp") +
		"&code_challenge=" + challenge + "&code_challenge_method=S256&state=st&nonce=n"
	r1, err := h.client.Get(authURL)
	if err != nil {
		t.Fatalf("authorize get: %v", err)
	}
	defer r1.Body.Close()
	r2, err := h.client.Get(r1.Header.Get("Location"))
	if err != nil {
		t.Fatalf("upstream get: %v", err)
	}
	defer r2.Body.Close()
	// Callback: upstream nonce mismatch must fail (no redirect to client).
	r3, err := h.client.Get(r2.Header.Get("Location"))
	if err != nil {
		t.Fatalf("callback get: %v", err)
	}
	defer r3.Body.Close()
	if r3.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502 on nonce mismatch, got %d body=%s", r3.StatusCode, slurp(r3.Body))
	}
}

func slurp(r io.Reader) string {
	b, _ := io.ReadAll(r)
	return string(b)
}
