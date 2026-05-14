package as

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

// AS is the assembled authorization server.
type AS struct {
	cfg    *Config
	states *stateStore
}

// New validates the config and returns an AS.
func New(cfg Config) (*AS, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	cfg.defaults()
	return &AS{cfg: &cfg, states: newStateStore()}, nil
}

// Config returns the live config (read-only).
func (a *AS) Config() *Config { return a.cfg }

// Handler returns an http.Handler covering all AS endpoints under PathPrefix.
//
// Routes (relative to PathPrefix):
//
//	GET  /authorize
//	POST /token
//	POST /register
//	GET  /idp/callback
//	POST /revoke
//	GET  /userinfo
//
// The host-root well-known endpoints (oauth-authorization-server,
// openid-configuration, jwks.json) are exposed as separate handler methods:
// MetadataHandler, OIDCMetadataHandler, JWKSHandler.
func (a *AS) Handler() http.Handler {
	r := chi.NewRouter()
	r.Get("/authorize", a.handleAuthorize)
	r.Post("/token", a.handleToken)
	r.Post("/register", a.handleRegister)
	r.Get("/idp/callback", a.handleIDPCallback)
	r.Post("/revoke", a.handleRevoke)
	r.Get("/userinfo", a.handleUserinfo)
	return r
}

func (a *AS) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	a.handleAuthorizeImpl(w, r)
}

func (a *AS) handleToken(w http.ResponseWriter, r *http.Request) {
	a.handleTokenImpl(w, r)
}

func (a *AS) handleRegister(w http.ResponseWriter, r *http.Request) {
	a.handleRegisterImpl(w, r)
}

func (a *AS) handleIDPCallback(w http.ResponseWriter, r *http.Request) {
	a.handleIDPCallbackImpl(w, r)
}

func (a *AS) handleRevoke(w http.ResponseWriter, r *http.Request) {
	a.handleRevokeImpl(w, r)
}

func (a *AS) handleUserinfo(w http.ResponseWriter, r *http.Request) {
	a.handleUserinfoImpl(w, r)
}

// MetadataHandler serves /.well-known/oauth-authorization-server (RFC 8414).
func (a *AS) MetadataHandler(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, a.metadata())
}

// OIDCMetadataHandler serves /.well-known/openid-configuration.
func (a *AS) OIDCMetadataHandler(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, a.metadata())
}

// JWKSHandler serves /.well-known/jwks.json — currently active public keys.
func (a *AS) JWKSHandler(w http.ResponseWriter, r *http.Request) {
	jwks, err := a.cfg.KeyManager.PublishJWKS(r.Context())
	if err != nil {
		http.Error(w, "jwks unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=3600")
	writeJSON(w, http.StatusOK, jwks)
}
