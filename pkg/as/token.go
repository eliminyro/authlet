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

// tokenResponse is the RFC 6749 §5.1 successful token endpoint response.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// handleTokenImpl dispatches on grant_type after parsing the form body.
func (a *AS) handleTokenImpl(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "form parse error")
		return
	}
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
	if !verifyPKCE(authCode.PKCEChallenge, verifier) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "pkce verification failed")
		return
	}
	a.mintAndWrite(w, r, authCode.UserID, authCode.ClientID, authCode.Resource, authCode.Scope, "")
}

// tokenRefresh handles the refresh_token grant with rotation + reuse
// detection: if the presented token has already been used, the entire
// family is revoked.
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
	a.mintAndWrite(w, r, rt.UserID, rt.ClientID, rt.Resource, rt.Scope, rt.FamilyID)
	// MarkUsed AFTER successful mint+write (race: best-effort).
	newHash := hashCode(a.lastIssuedRefresh(r.Context()))
	_ = a.cfg.Storage.RefreshTokens().MarkUsed(r.Context(), hash, newHash)
}

// mintAndWrite issues a fresh access+refresh pair, writes the HTTP response,
// and stashes the new refresh plaintext on the request so the caller can
// MarkUsed the old token.
func (a *AS) mintAndWrite(w http.ResponseWriter, r *http.Request, userID, clientID, resource, scope, familyID string) {
	priv, kid, err := a.cfg.KeyManager.Signer(r.Context())
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "signer unavailable")
		return
	}
	now := time.Now()
	exp := now.Add(a.cfg.AccessTokenTTL)
	extra := map[string]any{}
	if a.cfg.AdditionalClaims != nil {
		for k, v := range a.cfg.AdditionalClaims(userID, clientID, resource) {
			extra[k] = v
		}
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
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "sign failed")
		return
	}
	refreshPlain, err := randomID(32)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "refresh gen failed")
		return
	}
	if familyID == "" {
		familyID = uuid.NewString()
	}
	rt := storage.RefreshToken{
		TokenHash: hashCode(refreshPlain),
		FamilyID:  familyID,
		ClientID:  clientID,
		UserID:    userID,
		Resource:  resource,
		Scope:     scope,
		ExpiresAt: now.Add(a.cfg.RefreshTokenTTL),
	}
	if err := a.cfg.Storage.RefreshTokens().Save(r.Context(), rt); err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "refresh save failed")
		return
	}
	a.stashIssuedRefresh(r, refreshPlain)
	_ = a.cfg.Storage.Clients().Touch(r.Context(), clientID)
	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken:  at,
		TokenType:    "Bearer",
		ExpiresIn:    int(a.cfg.AccessTokenTTL.Seconds()),
		RefreshToken: refreshPlain,
		Scope:        scope,
	})
}

// Per-request stash of the last issued refresh plaintext so the refresh path
// can MarkUsed without re-deriving it.
type ctxKey int

const ctxKeyIssuedRefresh ctxKey = 1

func (a *AS) stashIssuedRefresh(r *http.Request, plain string) {
	*r = *r.WithContext(context.WithValue(r.Context(), ctxKeyIssuedRefresh, plain))
}

func (a *AS) lastIssuedRefresh(ctx context.Context) string {
	v, _ := ctx.Value(ctxKeyIssuedRefresh).(string)
	return v
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

var errNotImplemented = errors.New("not implemented")
