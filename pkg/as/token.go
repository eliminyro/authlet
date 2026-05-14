package as

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/eliminyro/authlet/pkg/jwt"
	"github.com/eliminyro/authlet/pkg/storage"
	"github.com/google/uuid"
)

// tokenResponse is the RFC 6749 §5.1 successful token endpoint response,
// extended with the optional OIDC id_token field.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// handleTokenImpl dispatches on grant_type after parsing the form body
// and authenticating the client.
func (a *AS) handleTokenImpl(w http.ResponseWriter, r *http.Request) {
	// RFC 6749 §5.1: token endpoint responses (success and error) MUST
	// include Cache-Control: no-store and Pragma: no-cache. Set early so
	// every code path inherits the headers.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "form parse error")
		return
	}
	authedClientID, err := a.authenticateClient(r.Context(), r)
	if err != nil {
		switch {
		case errors.Is(err, errClientAuthRequired):
			w.Header().Set("WWW-Authenticate", `Basic realm="authlet"`)
			writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "client authentication required")
		default:
			writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		}
		return
	}
	// Overwrite r.Form["client_id"] with the authenticated value so the
	// grant-type branches see the verified client_id.
	r.Form.Set("client_id", authedClientID)

	grant := r.Form.Get("grant_type")
	switch grant {
	case "authorization_code":
		a.tokenAuthCode(w, r)
	case "refresh_token":
		a.tokenRefresh(w, r)
	default:
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "grant_type must be authorization_code or refresh_token")
	}
}

// tokenAuthCode handles the authorization_code grant: consume the code,
// verify client/redirect/resource/PKCE binding, then mint tokens.
func (a *AS) tokenAuthCode(w http.ResponseWriter, r *http.Request) {
	code := r.Form.Get("code")
	clientID := r.Form.Get("client_id")
	verifier := r.Form.Get("code_verifier")
	redirect := r.Form.Get("redirect_uri")
	resource := r.Form.Get("resource")
	if code == "" || clientID == "" || verifier == "" || redirect == "" || resource == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "missing parameters")
		return
	}
	authCode, err := a.cfg.Storage.Codes().ConsumeOnce(r.Context(), hashCode(code))
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "code invalid")
		return
	}
	if authCode.ClientID != clientID || authCode.RedirectURI != redirect || authCode.Resource != resource {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "binding mismatch")
		return
	}
	// Defense-in-depth: only S256 is accepted. /authorize already
	// enforces this, but a malicious or buggy storage driver could hand
	// us a different method.
	if authCode.PKCEMethod != "S256" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "pkce method unsupported")
		return
	}
	if !verifyPKCE(authCode.PKCEChallenge, verifier) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "pkce verification failed")
		return
	}
	refreshPlain, err := randomID(32)
	if err != nil {
		a.cfg.Logger.Error("token: refresh gen failed", "err", err, "client_id", clientID)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "refresh gen failed")
		return
	}
	// New code grant: save the refresh token before signing so any
	// storage failure aborts cleanly without leaking a partially-issued
	// session.
	if err := a.saveRefreshToken(r.Context(), refreshPlain, "", authCode.ClientID, authCode.UserID, authCode.Resource, authCode.Scope); err != nil {
		a.cfg.Logger.Error("token: refresh save failed", "err", err, "client_id", clientID)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "refresh save failed")
		return
	}
	a.mintAndWrite(w, r, authCode.UserID, authCode.ClientID, authCode.Resource, authCode.Scope, refreshPlain)
}

// tokenRefresh handles the refresh_token grant with rotation + reuse
// detection: if the presented token has already been used, the entire
// family is revoked.
//
// Rotation order is critical to avoid two failure modes:
//  1. TOCTOU race: two concurrent goroutines both pass the ReplacedBy
//     guard and both rotate the same token. Closed by the atomic
//     check-and-set in MarkUsed.
//  2. Session bricking: a transient storage failure after MarkUsed
//     leaves the old token marked used but the new token never persisted,
//     so the user is locked out forever. Closed by saving the new token
//     BEFORE MarkUsed and treating any failure as a recoverable 500.
//
// Resulting order:
//  1. Get the stored token (rejects family-revoked etc).
//  2. Reuse check: rt.ReplacedBy != "" -> revoke family + 400.
//  3. Generate new plaintext + hash.
//  4. Save the new refresh token (inheriting FamilyID). On failure
//     return 500 — the old token is still valid and the user can retry.
//  5. MarkUsed(oldHash, newHash) — atomic check-and-set. On
//     ErrAlreadyConsumed we lost the race; revoke the family. The new
//     token row is now orphaned but family revocation invalidates it.
//  6. Mint access (+ optional id) token, write the response.
func (a *AS) tokenRefresh(w http.ResponseWriter, r *http.Request) {
	refresh := r.Form.Get("refresh_token")
	clientID := r.Form.Get("client_id")
	resource := r.Form.Get("resource")
	if refresh == "" || clientID == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "missing parameters")
		return
	}
	hash := hashCode(refresh)
	rt, err := a.cfg.Storage.RefreshTokens().Get(r.Context(), hash)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh invalid")
		return
	}
	if rt.ClientID != clientID {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "client mismatch")
		return
	}
	// Reuse detection: if this token already has a replacement, family revoke.
	if rt.ReplacedBy != "" {
		a.cfg.Logger.Warn("token: refresh reuse detected", "client_id", clientID, "family_id", rt.FamilyID)
		_ = a.cfg.Storage.RefreshTokens().RevokeFamily(r.Context(), rt.FamilyID)
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh reused")
		return
	}
	if time.Now().After(rt.ExpiresAt) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh expired")
		return
	}
	if resource == "" {
		resource = rt.Resource
	} else if resource != rt.Resource {
		writeOAuthError(w, http.StatusBadRequest, "invalid_target", "resource mismatch")
		return
	}
	refreshPlain, err := randomID(32)
	if err != nil {
		a.cfg.Logger.Error("token: refresh gen failed", "err", err, "client_id", clientID)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "refresh gen failed")
		return
	}
	newHash := hashCode(refreshPlain)
	// Save the new token BEFORE MarkUsed. If this fails, the old token
	// is still valid so the user can retry rather than being permanently
	// locked out (regression guard against the F1-era ordering).
	if err := a.saveRefreshToken(r.Context(), refreshPlain, rt.FamilyID, rt.ClientID, rt.UserID, resource, rt.Scope); err != nil {
		a.cfg.Logger.Error("token: refresh save failed", "err", err, "client_id", clientID, "family_id", rt.FamilyID)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "refresh save failed")
		return
	}
	// Atomic check-and-set on the old token. If we lose the race, revoke
	// the family — the new token we just saved is orphaned but family
	// revocation prevents anyone from using it.
	if err := a.cfg.Storage.RefreshTokens().MarkUsed(r.Context(), hash, newHash); err != nil {
		if errors.Is(err, storage.ErrAlreadyConsumed) {
			a.cfg.Logger.Warn("token: refresh rotation race lost; orphaned new token will be inert via family revoke", "client_id", clientID, "family_id", rt.FamilyID)
			_ = a.cfg.Storage.RefreshTokens().RevokeFamily(r.Context(), rt.FamilyID)
		} else {
			a.cfg.Logger.Error("token: MarkUsed failed", "err", err, "client_id", clientID, "family_id", rt.FamilyID)
		}
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh reused")
		return
	}
	a.mintAndWrite(w, r, rt.UserID, rt.ClientID, resource, rt.Scope, refreshPlain)
}

// saveRefreshToken persists a freshly generated refresh-token plaintext
// under the given FamilyID. When familyID is empty a fresh family is
// minted (i.e. a new authorization-code grant).
func (a *AS) saveRefreshToken(ctx context.Context, plain, familyID, clientID, userID, resource, scope string) error {
	if familyID == "" {
		familyID = uuid.NewString()
	}
	now := time.Now()
	return a.cfg.Storage.RefreshTokens().Save(ctx, storage.RefreshToken{
		TokenHash: hashCode(plain),
		FamilyID:  familyID,
		ClientID:  clientID,
		UserID:    userID,
		Resource:  resource,
		Scope:     scope,
		ExpiresAt: now.Add(a.cfg.RefreshTokenTTL),
	})
}

// mintAndWrite signs a fresh access (+ optional id) token and writes the
// HTTP response. The refresh token has already been persisted by the
// caller — this function only signs JWTs and writes the body, never
// saves refresh tokens. Splitting save-then-mint is what guarantees the
// S1 invariant (no marked-used-but-not-saved window).
func (a *AS) mintAndWrite(w http.ResponseWriter, r *http.Request, userID, clientID, resource, scope, refreshPlain string) {
	at, idTokenStr, err := a.mintTokens(r.Context(), userID, clientID, resource, scope)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	_ = a.cfg.Storage.Clients().Touch(r.Context(), clientID)
	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken:  at,
		TokenType:    "Bearer",
		ExpiresIn:    int(a.cfg.AccessTokenTTL.Seconds()),
		RefreshToken: refreshPlain,
		IDToken:      idTokenStr,
		Scope:        scope,
	})
}

// mintTokens signs the access token and, when "openid" is in scope, the
// id_token. It does NOT touch the refresh-token store. Returns short
// error sentinels that the caller maps to OAuth 500 bodies; all log
// emission for these failures happens here.
func (a *AS) mintTokens(ctx context.Context, userID, clientID, resource, scope string) (accessToken, idTokenStr string, err error) {
	priv, kid, err := a.cfg.KeyManager.Signer(ctx)
	if err != nil {
		a.cfg.Logger.Error("token: signer unavailable", "err", err, "client_id", clientID)
		return "", "", errSignerUnavailable
	}
	now := time.Now()
	exp := now.Add(a.cfg.AccessTokenTTL)
	extra := map[string]any{}
	for k, v := range a.safeAdditionalClaims(userID, clientID, resource) {
		extra[k] = v
	}
	claims := jwt.Claims{
		Issuer:    a.cfg.Issuer,
		Subject:   userID,
		Audience:  resource,
		ClientID:  clientID,
		Scope:     scope,
		IssuedAt:  now.Unix(),
		ExpiresAt: exp.Unix(),
		JTI:       uuid.NewString(),
		Extra:     extra,
	}
	at, err := jwt.Sign(claims, kid, priv)
	if err != nil {
		a.cfg.Logger.Error("token: sign failed", "err", err, "client_id", clientID)
		return "", "", errSignFailed
	}
	if !containsScope(scope, "openid") {
		return at, "", nil
	}
	idClaims := jwt.Claims{
		Issuer:    a.cfg.Issuer,
		Subject:   userID,
		Audience:  clientID, // OIDC: id_token aud = client_id, not resource
		IssuedAt:  now.Unix(),
		ExpiresAt: exp.Unix(),
		JTI:       uuid.NewString(),
		Extra:     map[string]any{},
	}
	email, verified, name, pic := a.safeIDTokenClaims(userID)
	if email != "" {
		idClaims.Extra["email"] = email
		idClaims.Extra["email_verified"] = verified
	}
	if name != "" {
		idClaims.Extra["name"] = name
	}
	if pic != "" {
		idClaims.Extra["picture"] = pic
	}
	idStr, err := jwt.Sign(idClaims, kid, priv)
	if err != nil {
		a.cfg.Logger.Error("token: id_token sign failed", "err", err, "client_id", clientID)
		return "", "", errIDTokenSignFailed
	}
	return at, idStr, nil
}

var (
	errSignerUnavailable = errors.New("signer unavailable")
	errSignFailed        = errors.New("sign failed")
	errIDTokenSignFailed = errors.New("id_token sign failed")
)

// safeAdditionalClaims invokes the configured AdditionalClaims hook and
// recovers from panics so a misbehaving claim provider cannot crash the
// token endpoint. Returns nil on panic or when the hook is nil. Logs at
// ERROR level on recovery so the broken hook is visible to operators.
func (a *AS) safeAdditionalClaims(userID, clientID, resource string) (m map[string]any) {
	defer func() {
		if rec := recover(); rec != nil {
			a.cfg.Logger.Error("token: AdditionalClaims hook panicked", "recover", rec, "client_id", clientID)
			m = nil
		}
	}()
	if a.cfg.AdditionalClaims == nil {
		return nil
	}
	return a.cfg.AdditionalClaims(userID, clientID, resource)
}

// safeIDTokenClaims invokes the configured IDTokenClaims hook and recovers
// from panics so a misbehaving claim provider cannot crash /token. Returns
// zero values on panic or when the hook is nil. Logs at ERROR level on
// recovery.
func (a *AS) safeIDTokenClaims(userID string) (email string, emailVerified bool, name, picture string) {
	defer func() {
		if rec := recover(); rec != nil {
			a.cfg.Logger.Error("token: IDTokenClaims hook panicked", "recover", rec, "user_id", userID)
			email, emailVerified, name, picture = "", false, "", ""
		}
	}()
	if a.cfg.IDTokenClaims == nil {
		return "", false, "", ""
	}
	return a.cfg.IDTokenClaims(userID)
}

// verifyPKCE returns true if sha256(verifier) base64url-no-pad equals the
// stored S256 challenge.
func verifyPKCE(challenge, verifier string) bool {
	sum := sha256.Sum256([]byte(verifier))
	enc := strings.TrimRight(base64.URLEncoding.EncodeToString(sum[:]), "=")
	enc = strings.ReplaceAll(enc, "+", "-")
	enc = strings.ReplaceAll(enc, "/", "_")
	return enc == challenge
}

// containsScope reports whether the whitespace-separated scope list
// contains the given needle.
func containsScope(scope, needle string) bool {
	for _, s := range strings.Fields(scope) {
		if s == needle {
			return true
		}
	}
	return false
}
