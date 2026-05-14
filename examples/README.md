# Examples

Two reference embeddings of `authlet`:

- `hilo-embed/` — chi router, single Google upstream IdP. Mirrors how Hilo wires the AS.
- `memory-embed/` — stdlib `http.ServeMux`, federated upstream pointing at Hilo's authlet, dual-auth (API key OR Bearer JWT) on `/mcp`.

These files do not run as-is — they reference placeholder app glue (`authletStorage()`, your user resolver). They compile cleanly (so `go build ./...` stays green) but the placeholders return nil/empty values, so calling `main` would panic at runtime. Treat them as a checklist when wiring authlet into a real service.

For a runnable end-to-end demo, see `cmd/authletd`.
