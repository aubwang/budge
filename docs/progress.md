# Progress

Contract: BUILD_HANDOFF.md (copied verbatim; no old implementation imported).

## Slice 1 — verified

Acceptance: one-use invitation over verified TLS; owner login/service credential entry/exact standing permission; enrolled connector reaches TLS mock with unchanged body and fixture authentication; client never sees credential; unenrolled/out-of-scope/revoked callers cannot dispatch, including reused connections; encrypted persistent state reopens only with correct unlock secret.

Choices: Go/SQLite as proposed. Official Go toolchain installed under ~/.local/share/budge-toolchain because Go was absent. No real credentials, upstream calls, or publication.

Evidence: `go test -race ./...`, `go vet ./...`, and `go build ./cmd/budge` passed. Integration tests cover connector + verified TLS + owner UI + SQLite + TLS mock, one-use enrollment, denied scopes, revoked identity on a reused connection, owner/device separation, browser/Host rejection, encrypted identity/database contents, startup lock, wrong unlock rejection, and persisted no-expiry permission. Restart testing found and fixed error-path cleanup before completion.

## Remaining

2. Complete standing gateway, streaming, revisions, scopes, limits, configuration.
3. MCP, immutable review, durable dispatch and results.
4. Failure semantics, concurrency, renewal, revocation and recovery tests.
5. Packaging, UI polish, documentation, CI and measured mock demo.

Real OpenCode/OpenRouter compatibility and real MCP-host compatibility are unverified.
