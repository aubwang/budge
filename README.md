# Budge

A self-hosted HTTP gateway: enroll a device and grant specific access while upstream credentials stay on the trusted machine. The fixed design is [BUILD_HANDOFF.md](BUILD_HANDOFF.md). Implementation status and evidence live in [docs/progress.md](docs/progress.md).

## Development

Requires Go 1.27.1. Run `go test -race ./...`, `go vet ./...`, and `go build -o bin/budge ./cmd/budge`. On the initial development box, Go is under `~/.local/share/budge-toolchain/go/bin`.

Dependencies are pinned in go.mod/go.sum: [modernc SQLite](https://pkg.go.dev/modernc.org/sqlite@v1.58.0), [Go x/crypto](https://pkg.go.dev/golang.org/x/crypto@v0.57.0), and [Go x/term](https://pkg.go.dev/golang.org/x/term@v0.46.0). The toolchain was downloaded from [Go's official distribution](https://go.dev/dl/) with its published SHA-256 checked. No old Budge code was imported.

## Initial local setup (Slice 1)

Run `bin/budge server --url https://localhost:8443`. Enter a server unlock secret and a separate initial owner password at the hidden prompts (12 characters minimum). Open `http://127.0.0.1:8080`, sign in, add a service, and create an invitation. Credentials are write only. The invitation is shown once, expires in five minutes, and must be transferred privately.

On the device, run `bin/budge enroll`, paste the invitation at its hidden prompt, and choose an identity passphrase. In the owner UI, grant that device an exact method/path permission. Run `bin/budge connect` and use `http://127.0.0.1:7777/s/SERVICE/PATH` from an ordinary HTTP client. If the client demands an API key, `budge-local` is a non-secret placeholder; it is stripped. No real-provider compatibility is claimed yet.

Generate an OpenCode routing fragment with `bin/budge connect --print-opencode-config`. Configuration fields were checked against official OpenCode documentation; the installed underlying executable reports 1.18.20, but real OpenCode/OpenRouter behavior has not been tested.

The server and connector must be unlocked after each restart. Automated input uses dedicated `--unlock-fd`, `--owner-password-fd`, `--invitation-fd`, and `--passphrase-fd` streams; never pass secret values as flags or put them in an .env file. Each descriptor supplies one line, at most 64 KiB. Keep local identity and database directories private. Losing the unlock secret loses access to the encrypted material.

The server's default device and owner listeners bind loopback. Set `--device-listen` and `--url` for a remotely reachable device endpoint. The owner UI stays on loopback; remote administration uses an SSH tunnel preserving the configured Host. Only enrolled client certificates authenticate device access; network restrictions alone grant no access.

## Current boundaries

Exact/subtree rules, method lists, optional expiry, standing/approval-required modes, service revision replacement and revocation are available. Direct HTTP rejects approval-required routes. MCP exposes budge_services, budge_request and budge_request_status through the running connector's private Unix socket. HTTPS upstreams are required; private, loopback and link-local addresses are denied. Integration tests inject a local TLS mock transport in test code only. Paths use the handoff's conservative ASCII grammar. HTTP request bodies are limited to 8 MiB. Local processes can use the connector's device-wide authority. A trusted upstream that reflects its own credential can expose it in a response; Budge is not a response DLP filter.

This is work in progress, not a completed or published v1. Do not restore an old database and resume service: an old copy may resurrect access and, once durable requests exist, execution authority.

HTTP uses bounded 10-second connection/TLS and 30-second response-header timeouts, a five-minute upstream/read idle timeout, and a 30-second downstream write timeout. There is no short total response timeout. Responses stream with bounded buffers and backpressure. There are four concurrent requests per device and 32 globally. There are no Budge application retries; fresh outbound HTTP/1 transports also avoid pooled-connection replay. HTTP audit metrics contain IDs, method, status, duration and byte counts, not raw paths/queries or bodies.

## Approved requests through MCP

Start `budge connect`, then configure your MCP host to launch `budge mcp` (or `budge mcp --socket /absolute/private/connect.sock`). It never prompts on protocol streams; unlock the connector first. The socket directory is user-owned mode 0700 and the socket is mode 0600.

Submit service, method, conservative path, optional raw query, application header object, UTF-8 body (64 KiB maximum), and a client-generated `idempotency_key`. Reuse that key only for the identical submission. The result returns a durable request ID and state. Check it with `budge_request_status`; optional `wait_seconds` is 0–15. An approval-required permission allows asking, not sending. With no scope, submission is denied.

The owner inbox links to the exact stored HTTP request, including query, headers, body, expiry, and snapshot digest. Approve or deny using that page. Budge freezes the snapshot, checks the expected digest and current authority, and claims dispatch transactionally before sending. It makes one automatic dispatch attempt. This is not exactly-once provider execution. `outcome_unknown` requires checking the provider before creating a new request.

Approval expires after ten minutes, including time spent queued after approval. Standing MCP requests have a one-minute queue deadline. Twenty pending approvals per device are allowed. MCP results retain at most 1 MiB; truncated and incomplete responses are explicitly marked. Terminal payloads/results are purged after 24 hours; key/digest/status tombstones remain to prevent key reuse. Payloads are encrypted but still sensitive while unlocked. Routine logs exclude payloads, query strings and upstream credentials.
