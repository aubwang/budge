# Progress — 2026-09-10

Contract: BUILD_HANDOFF.md, copied verbatim from the requested handoff. No old implementation was imported. All upstream fixtures and credentials used so far are synthetic. The authorized autonomous implementation phase ends at the live-provider decision below.

| Slice | Acceptance checks stated before implementation | Result |
|---|---|---|
| 1 | One-use TLS enrollment; owner setup/service entry/exact standing grant; connector reaches mock with fixture authentication and unchanged bytes; unenrolled/out-of-scope/revoked callers denied; encrypted startup and identity state. | Verified and committed `1881255`. |
| 2 | Method/subtree scopes and overlap rejection; service revisions; header/URL/destination boundaries; progressive two-hop SSE, cancellation, size/concurrency limits; generated nonsecret config. | Verified against mocks and committed `d3e4e84`. Real provider test intentionally pending. |
| 3 | Three MCP tools through private connector socket; full immutable request review; approval-before-write; digest binding; deduplication; device-scoped results. | Verified with a real SDK stdio subprocess and TLS mock; committed `bdfe7c1`. |
| 4 | Concurrent decisions/claims; expiry/revocation/rotation; post-receipt connection loss and process crash without resend; certificate renewal; bounded results/retention and audit exclusions. | Race/failure checks passed; committed `9f53def`. |
| 5 | Linux/container builds; owner-loopback exposure and clean install; UI/docs/CI/demo; existing client/host checks; measured streaming latency, memory and concurrency. | Verified locally: race suite, vet/formatting, Linux builds, pinned container build, disposable setup, independent client/host checks and measurements passed. |

## Evidence and decisions

- Verification details: docs/verification.md. Reproducible setup/demo: docs/operator-guide.md. Architecture: DESIGN.md. Measurements: docs/measurements.md.
- Go 1.27.1 was downloaded from the official distribution with checksum verification because Go was absent; it is under `~/.local/share/budge-toolchain/go/bin`. Dependencies and container bases are pinned. CI actions were checked against official releases and pinned by hash.
- Full race suite, vet, formatting and Linux amd64/arm64 builds pass. ARM is cross-compiled, not executed on ARM hardware. Hosted CI has not run.
- curl 8.5.0 completed a mock HTTP round trip. OpenCode 1.18.20 connected to Budge as an MCP host and loaded the generated provider routing fragment using isolated config/data/cache/state directories. Its usual launcher loads a real key, so only the underlying executable was used, without provider credentials.
- Disposable container setup passed: UID 65532, read-only image, hidden unlock/owner prompts, owner login, packaged enrollment, encrypted identity, socket modes, authenticated default deny and no setup secrets in logs. Owner publication is loopback-only; probing this host's non-loopback addresses could not reach it.
- Actual process kill after the mock received a write yielded `outcome_unknown` on database reopen and no resend. Renewal preserved device identity/scopes; expiration and revocation were checked on existing TLS connections.
- First-byte medians: direct 0.063 ms, gateway 3.880 ms, added 3.817 ms in the documented local run. Combined live Go heap did not grow across a 64 MiB stream; this is not peak RSS or isolated server memory.
- Final review added custom explicit HTTP methods, reserved/metadata address checks, visible escaped body review, and base64 representation for heavily escaped results so JSON expansion cannot break MCP retrieval.

## Next major decision — live provider validation

No real OpenCode/OpenRouter generation request has been made. Proceeding needs the owner's authorization of a credential source, model and spend allowance. Keep that test isolated from existing agent configuration and use synthetic prompts. Gateway permissions are not a spending cap; provider/client limits must be considered explicitly.

No remote repository, PR, image push, website or release was published. Publication and release licensing remain separate owner decisions. No real credentials were read from the old repository or machine login stores.
