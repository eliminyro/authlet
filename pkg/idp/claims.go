// Package idp is a thin generic OIDC RP — authlet's AS uses it to forward
// user authentication to an upstream issuer (Google, another authlet, etc).
package idp

// Claims is the subset of OIDC ID token claims authlet cares about.
type Claims struct {
	Issuer        string `json:"iss"`
	Subject       string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
	Raw           map[string]any
}
