# Verification record

Status: all five implementation slices completed locally with synthetic data. No real OpenRouter request, spending, release/image publication, or old implementation import. This is a locally verified release candidate, not an assertion that every v1 compatibility requirement is finished.

| Boundary | Evidence |
|---|---|
| Independent identity | TLS enrollment generates separate device identities; other-device scope listing/result retrieval are denied; caller identity headers do not grant access. |
| Credential custody | TLS mock receives fixture auth; responses, owner readback, identity files, audit and container logs are checked for leakage. Client configuration examples contain only routing and a nonsecret placeholder. DB/WAL payloads and private keys are encrypted. Reflected upstream secrets remain an exclusion. |
| Standing permission | Exact/subtree/method/expiry tests, no-expiry restart persistence, overlap rejection, old-revision denial and explicit reissue. |
| Approval | Real SDK stdio subprocess → private socket → connector TLS → server; no send before approval, digest mismatch rejection, full escaped review, direct HTTP rejection and frozen-body tamper versus recorded approval. |
| Retry discipline | Concurrent same-key submissions, 16 concurrent decisions/claims, actual dropped response after receipt, actual process kill after receipt and database reopen. At most one automatic dispatch observed; uncertain requests never replay. |
| Pre-send failures | Approved requests encountering destination rejection, synthetic DNS failure, actual TLS trust failure, or cancellation before sending end as `failed/request_not_sent`, with one failure audit event and no upstream HTTP receipt. Duplicate submission, recovery and another dispatch call do not resend. Connection loss after receipt remains `outcome_unknown`. |
| Streaming and limits | Early SSE before provider close, cancellation through both hops, body/result limits, four requests per device, 32 globally, 20 pending approvals. Measurement method/results are in measurements.md. |
| Revocation/revisions | Device/permission revocation, service replacement/credential rotation/disable cancel pending and queued work. Existing device connections recheck revocation and certificate time. |
| TLS renewal | Client renews an expiring certificate under the same device ID and keeps scopes; server leaf renews under its unchanged root. |
| Destination/headers | Production transport rejects loopback; address tests cover private, mapped, link-local and metadata destinations. Redirect/header/path tricks do not widen access. All four static auth mechanisms are exercised. |
| Owner authority | Login/session/CSRF and Host/Origin tests; device identity cannot authenticate owner actions. Permissions and approvals refer to the owner. |
| Missing action targets | Authenticated, CSRF-protected permission revocation/service disable with empty or nonexistent IDs returns HTTP 400 and a clear not-found message. Audit history and existing service access remain unchanged. Existing-target cancellation checks still pass. |
| Persistence/recovery | Inode startup lock including hardlink alias, wrong-unlock rejection, encrypted local identity replacement, 24-hour retention with tombstones, restore access invalidation. |
| Existing HTTP client | curl 8.5.0 completed a synthetic request through both Budge hops to a TLS mock. |
| Existing MCP host | OpenCode 1.18.20 reported Budge connected via its local MCP configuration, in isolated XDG directories without provider credentials. Full tool interactions are additionally tested with official Go SDK v1.7.0. |
| Packaging | amd64 and arm64 Linux builds; local Docker image; disposable clean install checks hidden setup, owner login, enrollment, connector authentication/default deny, socket mode and loopback publication. arm64 is cross-compiled, not runtime-tested on ARM hardware. |
| CI | Workflow checks formatting, vet, race tests, Linux builds, container build and disposable setup smoke. These commands were run locally; no hosted CI run or publication has occurred. |

## Remaining decision

The real OpenCode → connector → Budge → OpenRouter generation smoke test needs separately authorized credentials, a selected model and a spend allowance. The installed OpenCode user wrapper loads a real key; tests bypassed that wrapper and did not inspect its credential store. OpenCode 1.18.20 loaded the manual configuration example and its resolved configuration contained `http://127.0.0.1:18782/s/openrouter/v1` and `budge-local`. This is configuration validation, not a live-provider generation test. Client-specific configuration generation has been removed from Budge.

The owner authorized configuring `origin` as `https://github.com/aubwang/budge.git` and committing/pushing the source to that repository. Release/image publication and release licensing remain separate owner decisions.

## Commands

```sh
go test -race ./... -timeout 120s
go vet ./...
test -z "$(gofmt -l cmd internal web)"
scripts/build-linux.sh
scripts/demo.sh
docker build -t budge-fresh:local .
python3 scripts/smoke-container.py
```

Optional independent host check, pointing at an installed executable that does not load personal credentials:

```sh
BUDGE_OPENCODE_BIN=/absolute/path/to/opencode go test ./internal/server -run TestExistingOpenCodeMCPHost -count=1 -v -timeout 60s
```
