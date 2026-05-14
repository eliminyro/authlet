# authlet

A small, embeddable OAuth 2.1 / OIDC Authorization Server library for Go.

Domain-agnostic. Pluggable upstream OIDC IdP. JWT access tokens, opaque
rotating refresh tokens, RFC 7591 DCR, PKCE S256, RFC 8707 audience binding,
RFC 9728 PRM helpers for MCP.

## Features

| Feature | Standard |
|---|---|
| AS metadata | RFC 8414 |
| OIDC Discovery | OIDC Core |
| Protected Resource Metadata | RFC 9728 |
| Dynamic Client Registration | RFC 7591 |
| Authorization Code + PKCE S256 | OAuth 2.1 |
| Resource Indicators | RFC 8707 |
| Refresh-token rotation with reuse detection | OAuth 2.1, RFC 6819 §5.2.2.3 |
| Token revocation | RFC 7009 |

## Packages

- `pkg/as` — Authorization Server endpoints (mountable as `http.Handler`)
- `pkg/rs` — Bearer middleware + JWKS client for resource servers
- `pkg/idp` — Generic OIDC RP for upstream authentication
- `pkg/jwt` — RS256 signing, JWKS publication, 30-day key rotation
- `pkg/crypto` — AES-GCM helper for at-rest encryption of signing keys
- `pkg/storage` — Storage interfaces + in-memory reference (`pkg/storage/memstore`)
- `pkg/mcp` — Optional helpers for MCP (PRM handler, WWW-Authenticate)

## Minimal embed

```go
import (
    "github.com/eliminyro/authlet/pkg/as"
    "github.com/eliminyro/authlet/pkg/idp"
    "github.com/eliminyro/authlet/pkg/jwt"
    "github.com/eliminyro/authlet/pkg/storage/memstore"
)

store := memstore.New()
mgr := jwt.NewManager(store.SigningKeys(), masterKey)
_ = mgr.Bootstrap(ctx)

upstream, _ := idp.NewOIDC(ctx, googleIssuer, clientID, secret, redirect, []string{"openid", "email"})

server, _ := as.New(as.Config{
    Issuer: "https://api.example.com", PathPrefix: "/oauth",
    Upstream: upstream, UserResolver: yourResolver,
    Storage: store, KeyManager: mgr,
})
```

Full embed examples for chi and stdlib mux: see [examples/](examples/).

## Development

- Run all tests: `go test ./...`
- Run integration tests: `go test -tags=integration ./...`
- Lint: `golangci-lint run ./...`
- Build the standalone binary: `go build ./cmd/authletd`
- Drive end-to-end with MCP Inspector: see [docs/INSPECTOR.md](docs/INSPECTOR.md)

## Status

v1.0.0 — first stable release. API stable within v1.x.

## License

GPL 3.0. See [LICENSE](LICENSE).
