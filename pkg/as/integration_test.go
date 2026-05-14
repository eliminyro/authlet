//go:build integration

package as

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
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
	"testing"
	"time"

	"github.com/eliminyro/authlet/pkg/idp"
	"github.com/eliminyro/authlet/pkg/jwt"
	"github.com/eliminyro/authlet/pkg/storage/memstore"
	jwtv5 "github.com/golang-jwt/jwt/v5"
)

// fakeOIDC stands in for Google in an end-to-end test.
type fakeOIDC struct {
	server   *httptest.Server
	key      *rsa.PrivateKey
	kid      string
	clientID string
	email    string
}

func newFakeOIDCIntegration(t *testing.T) *fakeOIDC {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	f := &fakeOIDC{key: k, kid: "fk1", clientID: "upstream-client", email: "alice@example.test"}
	mux := http.NewServeMux()
	var issuer string
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
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
		redir, _ := url.Parse(r.URL.Query().Get("redirect_uri"))
		q := redir.Query()
		q.Set("code", "upstream-code")
		q.Set("state", r.URL.Query().Get("state"))
		redir.RawQuery = q.Encode()
		http.Redirect(w, r, redir.String(), http.StatusFound)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		n := base64.RawURLEncoding.EncodeToString(k.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes())
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": f.kid, "n": n, "e": e}},
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		idTok := jwtv5.NewWithClaims(jwtv5.SigningMethodRS256, jwtv5.MapClaims{
			"iss": issuer, "sub": "google-sub", "aud": f.clientID,
			"email": f.email, "email_verified": true,
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

func TestE2E_FullAuthCodeFlowWithPKCE(t *testing.T) {
	fake := newFakeOIDCIntegration(t)
	defer fake.server.Close()

	mk := make([]byte, 32)
	if _, err := rand.Read(mk); err != nil {
		t.Fatal(err)
	}
	store := memstore.New()
	mgr := jwt.NewManager(store.SigningKeys(), mk)
	if err := mgr.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Reserve the AS URL before constructing the upstream provider so the
	// registered redirect_uri points back at the AS we're about to mount.
	// We use a TLS test server because authlet sets the state cookie with
	// Secure=true, and cookiejar will not send Secure cookies over plain HTTP.
	mux := http.NewServeMux()
	asSrv := httptest.NewTLSServer(mux)
	defer asSrv.Close()

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

	// HTTP client that trusts the test server's self-signed cert and follows
	// redirects manually so we can inspect each Location header.
	jar, _ := cookiejar.New(nil)
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec // test server
	httpClient := &http.Client{
		Jar:       jar,
		Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// DCR: client registers itself.
	dcrBody := `{"redirect_uris":["` + asSrv.URL + `/client/cb"]}`
	dcrReq, _ := http.NewRequest(http.MethodPost, asSrv.URL+"/oauth/register",
		strings.NewReader(dcrBody))
	dcrReq.Header.Set("Content-Type", "application/json")
	dcrResp, err := httpClient.Do(dcrReq)
	if err != nil {
		t.Fatalf("dcr: %v", err)
	}
	defer dcrResp.Body.Close()
	var dcr dcrResponse
	if err := json.NewDecoder(dcrResp.Body).Decode(&dcr); err != nil {
		t.Fatalf("dcr decode: %v", err)
	}
	if dcr.ClientID == "" {
		t.Fatalf("no client_id, status=%d", dcrResp.StatusCode)
	}

	// Client builds PKCE pair.
	verifier := "verifier-" + strings.Repeat("a", 50)
	sum := sha256.Sum256([]byte(verifier))
	challenge := strings.TrimRight(base64.URLEncoding.EncodeToString(sum[:]), "=")
	challenge = strings.ReplaceAll(strings.ReplaceAll(challenge, "+", "-"), "/", "_")

	// Step 1: /authorize → expect 302 to upstream.
	authURL := asSrv.URL + "/oauth/authorize?response_type=code&client_id=" + dcr.ClientID +
		"&redirect_uri=" + url.QueryEscape(asSrv.URL+"/client/cb") +
		"&resource=" + url.QueryEscape(asSrv.URL+"/api/mcp") +
		"&code_challenge=" + challenge + "&code_challenge_method=S256&state=client-state"
	r1, err := httpClient.Get(authURL)
	if err != nil {
		t.Fatalf("authorize get: %v", err)
	}
	defer r1.Body.Close()
	if r1.StatusCode != http.StatusFound {
		t.Fatalf("authorize status %d, body=%s", r1.StatusCode, readAll(r1.Body))
	}
	upstreamURL := r1.Header.Get("Location")

	// Step 2: Follow to upstream — fake OIDC immediately bounces back.
	r2, err := httpClient.Get(upstreamURL)
	if err != nil {
		t.Fatalf("upstream get: %v", err)
	}
	defer r2.Body.Close()
	if r2.StatusCode != http.StatusFound {
		t.Fatalf("upstream status %d", r2.StatusCode)
	}
	callbackURL := r2.Header.Get("Location")

	// Step 3: Follow back to authlet /idp/callback → expect 302 to client redirect with code.
	r3, err := httpClient.Get(callbackURL)
	if err != nil {
		t.Fatalf("callback get: %v", err)
	}
	defer r3.Body.Close()
	if r3.StatusCode != http.StatusFound {
		t.Fatalf("callback status %d, body=%s", r3.StatusCode, readAll(r3.Body))
	}
	clientRedirect, _ := url.Parse(r3.Header.Get("Location"))
	code := clientRedirect.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in client redirect: %s", clientRedirect.String())
	}

	// Step 4: Exchange code at /token.
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", dcr.ClientID)
	form.Set("code_verifier", verifier)
	form.Set("redirect_uri", asSrv.URL+"/client/cb")
	form.Set("resource", asSrv.URL+"/api/mcp")
	tokReq, _ := http.NewRequest(http.MethodPost, asSrv.URL+"/oauth/token",
		strings.NewReader(form.Encode()))
	tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r4, err := httpClient.Do(tokReq)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	defer r4.Body.Close()
	if r4.StatusCode != http.StatusOK {
		t.Fatalf("token status %d, body=%s", r4.StatusCode, readAll(r4.Body))
	}
	var tokResp tokenResponse
	if err := json.NewDecoder(r4.Body).Decode(&tokResp); err != nil {
		t.Fatalf("token decode: %v", err)
	}
	if tokResp.AccessToken == "" {
		t.Fatal("no access token")
	}

	// Step 5: Validate the access token via the manager's PublicKeyFunc.
	claims, err := jwt.Verify(tokResp.AccessToken, mgr.PublicKeyFunc(context.Background()), jwt.VerifyOptions{
		ExpectedIssuer:   asSrv.URL,
		ExpectedAudience: asSrv.URL + "/api/mcp",
	})
	if err != nil {
		t.Fatalf("verify access token: %v", err)
	}
	if claims.Subject != "user-alice@example.test" {
		t.Fatalf("sub mismatch: %q", claims.Subject)
	}
}

func readAll(r io.Reader) string {
	b, _ := io.ReadAll(r)
	return string(b)
}
