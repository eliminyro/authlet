// Package authlet is a small, embeddable OAuth 2.1 / OIDC Authorization Server
// library for Go. Domain-agnostic with a pluggable upstream OIDC IdP.
//
// The library is organized into sub-packages under pkg/. Apps embed pkg/as
// (the AS endpoints) and pkg/rs (the bearer middleware for protected
// resources). See https://github.com/eliminyro/authlet for details.
package authlet
