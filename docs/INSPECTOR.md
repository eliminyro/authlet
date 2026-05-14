# Testing authlet with MCP Inspector

`cmd/authletd` is the standalone AS for development. Combined with a tiny
mock resource server, it lets you drive the full OAuth 2.1 / OIDC flow with
the official [MCP Inspector](https://github.com/modelcontextprotocol/inspector).

## 1. Run authletd

You need an upstream OIDC issuer. The easiest is to point it at a real
Google OAuth client in dev mode (register `http://localhost:8089/oauth/idp/callback`
as a redirect URI) and pass:

```bash
go run ./cmd/authletd \
  --addr :8089 \
  --issuer http://localhost:8089 \
  --upstream-issuer https://accounts.google.com \
  --upstream-client-id <google-client-id> \
  --upstream-client-secret <google-client-secret> \
  --upstream-redirect http://localhost:8089/oauth/idp/callback \
  --prm-resource http://localhost:8090/mcp
```

### Persistent master key

By default authletd generates a fresh 32-byte AES-GCM master key at
startup and logs a warning. Every restart rotates the key, which
invalidates every previously-issued refresh token and forces every
client to re-authenticate. For repeated Inspector runs across
restarts, pin the key:

```bash
# Generate once and keep it somewhere safe (vault, .envrc, ...).
export AUTHLET_MASTER_KEY=$(openssl rand -base64 32)

go run ./cmd/authletd --master-key-b64 "$AUTHLET_MASTER_KEY" ...
# (--master-key-b64 defaults to AUTHLET_MASTER_KEY, so the explicit
# flag is optional when the env var is exported.)
```

The Manager also rotates signing keys on its own schedule when
`RunCleanup` ticks — so even with a stable master key, expect
in-flight tokens to switch kids every `RotationInterval`.

## 2. Run a stub resource server (`/mcp`)

Create `cmd/stub-rs/main.go` only when you need it — it is not part of the
shipped library. The stub validates Bearer tokens against authletd's JWKS
and returns 200 on success. See `examples/memory-embed/main.go` for the
shape; replace the dual-auth wrapper with the plain bearer middleware.

## 3. Run MCP Inspector

```bash
npx @modelcontextprotocol/inspector@latest \
  --url http://localhost:8090/mcp
```

Inspector will:
1. Receive 401 with WWW-Authenticate pointing at the PRM
2. Fetch the PRM, then AS metadata
3. POST /register (DCR)
4. Open the browser at /authorize (you log in via Google)
5. Exchange the returned code at /token
6. Connect to /mcp with a Bearer token

If all six steps succeed, you can ship to a real RS (Hilo / Memory MCP).

## 4. Troubleshooting

- **401 loop**: Inspector probably can't reach the PRM URL. Check the PRM
  is mounted at `/.well-known/oauth-protected-resource/...` and not under
  `/oauth/...`. Strict RFC 9728 puts it at host root.
- **POST to PRM URL gets 405**: `mcp.PRMHandler` is GET-only per
  RFC 9728 §3 (the PRM is a static metadata document; clients MUST
  fetch it via GET). If your client is POSTing, that's a client bug —
  the AS is correct to reject.
- **invalid_grant during /token**: PKCE verifier didn't match. Authletd
  expects S256 only. Inspector defaults to S256, so this usually means a
  resource mismatch between /authorize and /token — both must use the
  same `resource` parameter.
- **State cookie missing**: cmd/authletd sets the state cookie with
  `Secure` and `SameSite=Lax`. If you're on plain HTTP localhost, browsers
  may drop it. Use `--issuer http://127.0.0.1:8089` or terminate via TLS.
