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

Real OpenCode/OpenRouter compatibility and an independently deployed MCP host remain unverified; the official SDK host is exercised over a real stdio subprocess.

## Slice 2 — verified (mock upstreams)

Acceptance: method lists and exact/subtree scopes with transactional overlap rejection; service revisions invalidate old rules; header/URL/destination confinement; progressive two-hop SSE and cancellation; 8 MiB request / 4 per-device / 32 global limits; generated client configuration without credentials. Real OpenCode/OpenRouter remains pending unless separately authorized.

Verification: `go test -race ./... -timeout 90s`, `go vet ./...`, binary build and generated configuration check passed.

Slice 2 implementation: method lists, exact/subtree/optional-expiry rules, transactional overlap checks, explicit service revision replacement and permission revocation, header policies/private CIDRs, SQL migrations, scoped service listing, bounded request buffering, progressive response forwarding, cancellation and route-ID HTTP metrics. `connect --print-opencode-config` generates the OpenRouter base URL plus `budge-local` only.

Compatibility inspection: the underlying installed OpenCode reports 1.18.20. Its user launcher reads a real OpenRouter credential, so it was deliberately not executed. Official provider documentation/source supports `provider.openrouter.options.baseURL` and `apiKey`. No real-provider smoke test was run. Sources: https://opencode.ai/docs/providers/ and https://github.com/anomalyco/opencode/blob/dev/packages/opencode/src/provider/provider.ts .

Streaming test initially had a fixture error: its handler waited for cancellation without consuming the incoming body; fixed the mock to consume the finite request before streaming. It now confirms first event arrival while upstream stays open and cancellation of all four active streams. Tests also cover size limits, reserved/dynamic hop-by-hop headers, redirect refusal, path boundaries/encodings, overlap rejection, old-revision denial and explicit reissue.

## Slice 3 — verified (SDK host and mock upstream)

Acceptance: three SDK MCP tools through private connector socket; non-LLM write stays pending until owner approval; HTTP cannot bypass approval; full immutable snapshot/digest review without credential; deduplicated submissions; device-scoped status/results. Pin official MCP Go SDK v1.7.0 (official repository and Go module proxy checked).

Slice 3 evidence: full race suite, vet and binary build pass. Official SDK client launches a stdio subprocess, negotiates MCP, lists scopes and submits/polls over a private Unix socket and device TLS. Integration tests cover full escaped owner review, digest mismatch, approval-before-write, duplicate decision/submission, 12 concurrent same-key submissions, changed-key conflict, denial, cross-device result isolation, unknown MCP argument rejection and encrypted payload storage. Worker startup recovery, deadlines, cancellation on revisions/revocation, bounded results and retention are implemented; their failure-injection evidence is Slice 4.

## Slice 4 — verified

Acceptance: concurrent decisions/worker claims send at most once; expiry/revocation/revisions prevent claims; post-receipt connection loss and restart never resend; renewal preserves identity/scopes; bounded results and retention preserve tombstones; fixture payloads/credentials stay out of logs/config/unrelated responses.

Evidence: full race suite, vet, build pass. Added 16-way approval/claim race, real connection loss after upstream receipt, actual child-process kill after transmission and database reopen, interrupted-claim recovery, pending/queued invalidation for permission/device revocation, service/credential replacement and disable, expiry, changed snapshot versus recorded approval digest, 1 MiB truncation/503 preservation, 24-hour purge/tombstone dedup, 20-pending limit, old-revision dedup, certificate renewal, expired certificate on existing connection, server leaf renewal under unchanged root, production loopback rejection, all four static auth modes, restore access invalidation, and inode-based startup lock (including hardlink alias). Global concurrency/audit exclusion test covers 32 active requests over eight devices and rejection of a ninth device's request.

Renewal runs at connector startup and hourly, only during a certificate's final seven days, and atomically persists encrypted identity before switching certificates. The server renews its leaf during TLS handshakes. MCP dispatch has a two-minute total deadline; finite responses that cannot finish honestly report uncertainty/incompleteness. `server --recover-restored` invalidates old access and pending/queued requests before listening; it cannot reconstruct effects/keys absent from a backup.
