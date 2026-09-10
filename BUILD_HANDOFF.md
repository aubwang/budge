# Budge: fresh-repository design and build handoff

Design date: 2026-09-10. Status: proposed design; no implementation in the new repository exists yet.

This document is self-contained. Copy it into a fresh directory as `BUILD_HANDOFF.md`. It does not require the old Budge repository, its terminology, its architecture, or the preceding conversation. Do not import the old implementation or recreate its feature set.

## 1. Purpose and product boundary

Budge is a self-hosted HTTP gateway that lets an enrolled device use configured upstream services while the upstream credentials remain on a trusted machine. The owner chooses which requests have standing permission and which need individual approval.

The motivating example is an AI coding machine called **Donaid**. OpenCode on Donaid should be able to use OpenRouter through Budge without receiving an OpenRouter key. The same device should be able to propose an HTTP request to another service, wait for its owner to approve it, and retrieve the result.

This is primarily an open-source portfolio project. The owner is already comfortable with scoped provider tokens and a scoped 1Password service account. The objective is a useful, finished demonstration of product judgment and reliable systems engineering. It is not an emergency security migration or a requirement to outperform every existing gateway.

The product promise is: **configure a service on the trusted machine, enroll a device, and grant it specific access without giving it the upstream credential.**

### Requirements established by the user

- Self-contained deployment: a server container on a trusted machine and a small client on the agent machine.
- General HTTP services; no dependency on an LLM request schema.
- Standing permissions can last until revoked. Expiry is optional.
- Ordinary HTTP clients use standing permissions. Requests needing individual approval use MCP.
- A normal HTTP client changes its base URL, not its request body.
- Enrollment establishes a Budge caller identity. Tailscale can restrict network access but is optional.
- Every permission and approval has a human owner identity.
- Pending approval is visible to the agent and can be checked later.

### Recommended defaults introduced by this design

Use Go, SQLite, one owner, a local connector, mutual TLS for device authentication, and a small server-rendered owner UI. These are new design recommendations, not claims that the user previously selected a language or protocol.

Keep these outside v1: TLS interception, provider OAuth login/refresh flows, Codex/Claude subscription brokering, payment or dollar-budget enforcement, arbitrary code execution, operation packages, remote executors, multi-tenancy, teams/RBAC, a policy language, plugins, WebSockets, streaming uploads, and automatic interpretation of request intent by an LLM.

## 2. The experience to build

1. The owner starts the server container and opens its local UI.
2. The owner creates an `openrouter` service, enters its credential, and selects allowed request/response headers.
3. The owner creates an enrollment invitation for Donaid. On Donaid, `budge enroll` accepts that invitation through a hidden prompt.
4. The owner grants Donaid standing permission for `POST /v1/chat/completions` on that service, with no expiry.
5. Donaid runs `budge connect`. The connector reports the local service URL:
   `http://127.0.0.1:7777/s/openrouter/v1`.
6. OpenCode uses that base URL. If its provider configuration requires an API-key field, use a documented non-secret placeholder such as `budge-local`. Budge never forwards that placeholder as provider authentication.
7. A second service has an approval-required permission. An agent calls `budge_request` through MCP, receives `pending_approval`, and checks the request later.
8. The owner reviews the actual HTTP request in the UI and approves it. Budge dispatches it and makes its result available to the requesting device.
9. The owner revokes a permission or device. Subsequent authorization checks fail.

The OpenRouter service has fixed upstream base URL `https://openrouter.ai/api`; the relative path `/v1/chat/completions` therefore reaches `/api/v1/chat/completions`. No LLM-specific transformation occurs. OpenRouter documents this endpoint and SSE streaming in its [API reference](https://openrouter.ai/docs/api_reference/overview).

Verify the actual OpenCode provider configuration during implementation and document a tested client version. Do not invent a working configuration or claim compatibility from a mock alone.

## 3. Architecture and implementation shape

```text
Agent machine: Donaid                         Trusted machine

Existing HTTP client -- localhost HTTP --+
                                        |
MCP host -- stdio --> budge mcp -- socket +--> budge connect
                                                |
                                    authenticated TLS connection
                                                |
                                                +--> Budge server --> upstream HTTPS
                                                         |
                                                   SQLite + owner UI
```

Distribute one `budge` binary with `server`, `enroll`, `connect`, and `mcp` subcommands. The server is one process with one SQLite database. The container runs the server; the same codebase builds the client binary. Begin with Linux support.

- Use Go's HTTP/TLS libraries, a maintained SQLite driver, and the [official MCP Go SDK](https://github.com/modelcontextprotocol/go-sdk). Verify and pin supported dependency versions when implementing.
- Use embedded HTML templates, CSS, and a little JavaScript for polling. No frontend framework, separate frontend service, or external CDN is necessary.
- Use SQL migrations and ordinary queries. Avoid an ORM, a message broker, or a general repository/interface framework.
- The connector holds the device identity and forwards traffic. All authoritative permission decisions and upstream credential injection happen on the server.
- `budge mcp` uses a user-owned Unix socket to reach the running connector. It must not prompt for credentials on its protocol streams. Write diagnostics to stderr, never MCP stdout.

Suggested initial layout, created only as needed:

```text
cmd/budge/
internal/server/       owner UI and device HTTP endpoints
internal/client/       enrollment, connector, local socket
internal/access/       service definitions and permission decisions
internal/requests/     durable MCP request lifecycle
internal/upstream/     outbound HTTP and header handling
internal/store/        SQLite and encrypted fields
internal/mcp/          three MCP tools
web/                   templates and static assets
tests/integration/     mock upstreams and end-to-end fixtures
```

Use a single shared request validation and dispatch implementation for the two entry paths. HTTP streaming and durable MCP results need different response handling; they do not need separate policy engines.

## 4. Minimal domain model

| Concept | Meaning |
| --- | --- |
| Owner | The single authenticated human administrator. Has a stable ID, independent of display name or login session. |
| Device | An enrolled caller with a stable random ID, label, certificate/key metadata, and revocation state. All processes using its connector share this identity. |
| Service | An owner-configured upstream base URL, authentication configuration, header allowlists, enabled state, and security revision. |
| Permission | Owner-issued access for one device to one service revision, HTTP methods and paths, in either `standing` or `approval_required` mode. |
| Request | A durable MCP submission containing an immutable HTTP request snapshot, status, expiry, deduplication key, and eventual result. |
| Approval | An owner decision bound to one request ID and its snapshot digest. It permits one dispatch attempt. |
| Audit event | Metadata recording an enrollment, configuration change, permission decision, approval, revocation, or dispatch outcome. |

These are a vocabulary, not a mandate for one abstraction layer per noun. A permission stores `created_by_owner_id`; an approval stores `decided_by_owner_id` and decision time. No placeholder tenant IDs, organizational hierarchy, or separate resource-owner role in v1.

## 5. Enrollment, identity, and owner access

### Device enrollment

The server has its own TLS trust root. Initial configuration specifies the externally reachable server URL so its server certificate has the appropriate hostname/IP identity. The generated invitation contains this URL, the public trust root, and a random, one-use enrollment secret with a five-minute expiry.

The owner transfers the invitation through a trusted channel. It is a secret while valid: do not put it in command arguments, application logs, analytics, or persistent notes. Store only a hash of its secret on the server.

`budge enroll` generates a device key locally and submits a signed certificate request over TLS validated against the invitation's trust root and server hostname. The server atomically consumes the invitation and issues a certificate for the preallocated device ID. Enrollment grants identity only; it does not create service permissions. Treat duplicate or expired invitation use as failure.

Use standard certificate/CSR validation. The server sets the certificate's device identity and client-auth usage itself; it must not copy arbitrary identity, CA, or usage extensions from a CSR. Do not invent signed HTTP proofs or custom cryptography. Never disable TLS verification as a setup convenience.

Device endpoints require a valid Budge client certificate, except the enrollment endpoint, which requires the invitation. Extract caller identity from the verified certificate and look up the active device; never accept a caller-supplied identity header or device label as authentication.

Use 30-day client certificates and renew during the final seven days through an authenticated connector connection. Renewal requires an active device and a valid existing certificate. An expired device needs a new owner-issued enrollment invitation. Certificate renewal preserves the device ID; it does not create new permissions. Check device revocation and certificate validity on every request, including requests over existing connections. Renew server leaf certificates under the same trust root before expiry; replacing the trust root requires explicit client re-enrollment in v1.

Store the client private key in an encrypted local identity file unlocked when the connector starts. Accept the local passphrase through a hidden prompt or dedicated input stream; use a standard password KDF and authenticated encryption. Do not silently fall back to plaintext. Hardware-backed keys and OS-keychain integration are later work.

**Identity limitation:** this proves possession of enrolled key material, not physical-device integrity. A compromised Donaid can use its connector and may steal an unlocked software key. The credential-isolation claim concerns upstream credentials; Budge does not make a compromised device trustworthy.

### Owner access

Use one password-authenticated owner account with a modern password hash, server-side sessions, login throttling, CSRF protection, and escaped HTML. The session is a way to authenticate the owner's decision; v1 does not require passkey signatures or an external identity provider.

Keep the owner listener separate from the device listener. The packaged deployment publishes the owner UI only on host loopback. A remote owner uses an SSH tunnel; an optional documented HTTPS reverse proxy can be added later. Never publish the default owner listener on every host interface. Docker's internal bind address and its published host address are different settings: test the resulting exposure.

Reject unexpected Host/Origin values, disable CORS, and use HttpOnly, SameSite session cookies, with Secure cookies on HTTPS deployments. The local HTTP exception is restricted to the explicitly configured loopback UI. Device certificates cannot authenticate to owner APIs, and an approval URL is never an approval capability.

## 6. Services, credentials, and destinations

A service fixes an HTTPS origin and optional base path. It cannot contain URL userinfo, a query, or a fragment. Agents submit only a service ID and a relative path; they cannot choose the destination origin, credential, proxy, or secret placement.

Support four authentication configurations:

- `none`: no upstream credential.
- `bearer`: a server-held token in `Authorization`.
- `header`: a server-held value in an owner-selected header, such as `X-API-Key`.
- `basic`: server-held username/password encoded by the HTTP client library.

These are static credential mechanisms. A token called “OAuth” does not imply Budge implements its authorization or refresh flow. OAuth adapters and subscription authentication need separate future designs.

Encrypt provider credentials, server TLS private keys, and stored MCP payloads/results with authenticated encryption. Obtain the server's unlock secret through a hidden prompt or dedicated input stream at startup. It may be supplied by an existing secret manager, but no external secret manager is required. Do not put the unlock secret beside the encrypted database, in an image, a tracked file, an `.env` file, or a command-line flag. Bind encryption to record identity and purpose using associated data; generate nonces with a cryptographic RNG.

The initial self-contained mode requires unlocking after a server restart. Document this operating cost and the loss/recovery implications; do not claim unattended deployment without explaining where its unlock authority comes from. Owner password recovery and the vault unlock secret are separate concerns.

Credentials are write-only through the owner UI/API: return masked metadata, never a read-back endpoint. During setup, the trusted owner browser necessarily handles the entered credential. The gateway subsequently sends it only to the configured upstream.

Security-relevant changes to a service, including origin, authentication, credential replacement, or header policy, create a new revision. Existing permissions cease matching and undispatched MCP requests for the old revision cannot run. The UI explicitly offers review/reissue of permissions. Label-only edits need not change the revision. This conservative v1 rule also applies to credential rotation; avoid silently assuming a replacement credential represents the same account.

For outbound access:

- Validate TLS normally; do not follow redirects or use environment-derived outbound proxies.
- Reject loopback, link-local, multicast, unspecified, and private IP destinations by default, including IPv4-mapped forms. Validate DNS answers at connection time and connect to a validated address while preserving the configured TLS server name.
- An owner may explicitly allow a private destination for one service by naming its CIDR. This exception is visible in service setup and approval review. It does not authorize a new origin. Keep link-local/metadata destinations blocked. Integration fixtures use an explicit test-only loopback allowance that packaged deployments cannot enable.
- Build the target from the fixed base URL and validated relative path. Reject absolute-form targets, authority changes, `CONNECT`, `TRACE`, and protocol upgrades.

The upstream is a trusted recipient of its own credential. Budge cannot promise secrecy if an allowed upstream endpoint reflects that credential back in its response. Avoid such routes and document this limit; v1 is not a general data-loss-prevention filter.

## 7. Permission rules

A permission binds:

```text
device_id, service_id, service_revision
methods: explicit list
path: exact match OR segment-bounded subtree
mode: standing OR approval_required
created_by_owner_id, created_at
expires_at: optional
revoked_at: optional
```

Default deny. No permission means no request and no approval solicitation. `approval_required` means the device may ask for that request, not that it already has permission to execute it.

Paths are relative to the service base path. A subtree `/v1/items` matches that path and descendants separated by `/`; it does not match `/v1/items-other`. No regex, unrestricted glob, query predicate, or body predicate language.

For a device/service pair, reject active rules whose method/path sets overlap. This avoids implicit priority rules and an HTTP standing rule accidentally bypassing an MCP approval requirement. Validate overlap transactionally when adding or replacing rules. Expired, revoked, and obsolete-revision rules do not authorize requests.

Use a deliberately conservative v1 path grammar: ASCII paths starting with one `/`, no percent escapes, backslashes, interior empty segments, or `.`/`..` segments; allow a trailing slash and distinguish it for exact matches. Query strings remain separate and are preserved. Reject unsupported paths explicitly instead of decoding or rewriting them differently during matching and dispatch. Document this compatibility limit.

Permissions do not constrain query values, JSON fields, models, recipients, or spending. For example, permitting a payment endpoint is not a $50 spending cap. Continue using provider-level scopes and limits where needed.

Only the owner creates permissions. An agent's explanation cannot grant or widen access.

## 8. Standing HTTP behavior

The connector listens on `127.0.0.1` and exposes `/s/{service}/{relative-path}`. It preserves method, raw query, body bytes, and permitted headers, then forwards the request over its authenticated server connection. The server independently validates everything.

Because the connector is a device-wide capability, local processes that can reach it can use that device's access. It is not per-process authentication. Reject browser-originated requests, unexpected Host values, and CORS preflights; loopback alone is not protection against browser-driven requests. Keep the MCP Unix socket user-owned and inaccessible to other users.

- A matching standing permission permits immediate dispatch.
- A matching approval-required permission returns HTTP `403` with Budge error code `approval_required` and a short instruction to use MCP. It creates no pending approval.
- No match returns `403 permission_denied`; device authentication failures reject the TLS connection or return `401` if they reach the HTTP layer; disabled service or obsolete configuration fails closed.

Strip client `Authorization`, `Proxy-Authorization`, cookies, forwarding/identity headers, method-override headers, all Budge control headers, and the configured credential header. Forward only owner-allowed application headers; these reserved headers cannot be enabled by the allowlist. The initial request allowlist is `Accept` and `Content-Type`; additional headers require explicit service configuration. Reject invalid header names/values. Remove hop-by-hop headers and all headers named by `Connection`. Reconstruct Host and message framing using the HTTP library. Apply upstream authentication last.

Return upstream status, allowed end-to-end response headers, and response body bytes without an LLM-specific envelope. Default response headers include `Content-Type`, `Content-Encoding`, and `Retry-After`; allow additional headers explicitly. Never forward cookies, authentication headers, or hop-by-hop headers. Preserve errors from the provider; Budge-originated errors have a small documented JSON envelope.

Support finite request bodies up to 8 MiB and streaming responses, including SSE. Flush progressively, propagate cancellation, and apply backpressure. Do not parse SSE events, buffer the entire response, enable transparent decompression, or impose a short total timeout that breaks ordinary generation. Use bounded connection/header timeouts and a documented generous stream-idle timeout. A failure after response bytes were sent terminates the stream; do not append a fabricated JSON error.

Go's [ReverseProxy documentation](https://pkg.go.dev/net/http/httputil) covers response flushing; it does not replace an end-to-end streaming test through both Budge hops.

Budge performs no application-level automatic retries. Review the HTTP transport's own replay behavior as well, especially for approved requests; the [Go HTTP transport documentation](https://pkg.go.dev/net/http#Transport) describes automatic retry conditions. A caller or provider may independently retry. Budge does not promise one effect for arbitrary HTTP clients.

HTTP request/response bodies are not persisted. Audit device, service, permission, method, a safe route identifier, status, duration, and byte counts. Exclude raw queries and sensitive paths from routine logs.

## 9. MCP interface and pending approval

Expose three tools through `budge mcp`:

| Tool | Contract |
| --- | --- |
| `budge_services` | List only services and active permission scopes available to the authenticated device. Include which scopes need approval. |
| `budge_request` | Submit one finite HTTP request with a required client-generated idempotency key. Return its request ID and current state promptly. |
| `budge_request_status` | Retrieve that device's request status/result. Optional bounded wait, at most 15 seconds, reduces polling. |

`budge_request` accepts `service`, `method`, `path`, optional raw `query`, permitted `headers`, a UTF-8 `body` string, and `idempotency_key`. The body may contain JSON but Budge does not reserialize it. Limit body size to 64 KiB so full review is practical; binary bodies, uploads, and streaming results through MCP are outside v1. Unknown arguments fail validation.

Example tool result:

```json
{
  "request_id": "req_example",
  "status": "pending_approval",
  "expires_at": "2026-09-10T12:10:00Z",
  "next_action": "Call budge_request_status with this request_id. Do not resubmit with a new idempotency key.",
  "poll_after_ms": 3000
}
```

This is an application result, not a new MCP protocol state. Use structured tool output and a readable text representation, with SDK-supported version negotiation. The [MCP tool result specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) and [stdio transport specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports) provide the baseline; no experimental task or elicitation feature is required.

For a standing scope, the MCP submission is queued immediately. For an approval-required scope, it becomes pending. Both use the same durable execution lifecycle and eventually expose an HTTP status, allowed response headers, and a bounded UTF-8 or base64 response body. The base64 option is for representing returned bytes, not for approving opaque binary request bodies.

Only the originating active device and the owner can see a request/result. A guessable or leaked request ID does not authorize access. Status polling and reconnecting never dispatch anything.

## 10. Approval and execution lifecycle

At submission, validate the request and persist an immutable snapshot containing device ID, service ID/revision, permission ID, fixed effective URL, method, allowed application headers, exact body bytes, credential record/version reference, and approval expiry. Do not include the credential value. Serialize this fixed structure deterministically, store the exact serialized bytes, and compute a versioned SHA-256 digest over them.

The UI renders this stored snapshot and its digest. It shows the device, service/account label, method, effective URL including query, headers, body, and expiry. Escape all supplied text. Do not render request content as HTML or hide unreviewed content behind a misleading summary. An optional agent explanation is visibly untrusted and cannot substitute for the actual request.

Approval is a CSRF-protected owner action identifying the request and expected digest. The transaction verifies the snapshot, pending state, expiry, and still-valid device/service/permission. It records the owner decision and moves the request to `queued`. Denial is terminal. The owner cannot edit a pending request; changed content requires a new submission and new approval.

```text
approval-required submission --> pending_approval --> queued
                                      |                 |
                                denied/expired/         | atomic dispatch claim
                                  cancelled             v
standing submission ----------------> queued ------> dispatching
                                                        |
                                           completed / failed / outcome_unknown
```

`queued` requests can also expire or be cancelled before dispatch. Expiry for an approved request is the original approval deadline, not an unlimited execution window. Standing submissions use a short documented queue deadline.

The worker atomically claims a queued request and records `dispatching` before any upstream transmission. In the same transaction it checks current device/service/permission validity and the deadline. Only the successful claimant may send. This claim is the authorization boundary: revocation prevents later claims, but cannot retract a request already claimed or running. Ordinary HTTP dispatch uses an equivalent current-state authorization boundary. Revocation and service changes cancel affected pending/queued requests with a specific reason; they never rewrite a running request's snapshot.

Make **one automatic dispatch attempt**. Disable redirects and both explicit and transport-level retries for this path. A duplicate approval, duplicate worker wakeup, polling, or restart must not send the request again. Test the real HTTP client's behavior when a connection breaks after the upstream receives a request.

On restart, leave pending requests pending until expiry; process still-valid queued requests; mark requests found in `dispatching` as `outcome_unknown` and never automatically resend them. A timeout or connection loss after transmission may mean the upstream performed the effect. `outcome_unknown` must tell the owner and agent that checking the provider is necessary before trying again.

Use `failed` only when Budge can establish a definite local failure, such as rejection before sending. A complete upstream HTTP response, including 4xx/5xx, is `completed` with its actual HTTP status. Record truncated/incomplete results explicitly; they must never trigger a retry.

This is at-most-one automatic dispatch per durable request, **not exactly-once upstream execution**. There is no atomic transaction spanning SQLite and an arbitrary provider.

### Submission deduplication

Enforce a unique `(device_id, idempotency_key)` constraint. The same key and identical normalized submission return the original request; changed submission data returns a conflict. Store the submission comparison digest separately from the execution snapshot digest so service changes do not turn a retry into a new operation.

Lookup and authorization remain device-scoped. A duplicate can return an old status even if its service revision is obsolete, but it never acquires new execution authority. Retain a small key/status/digest tombstone when payloads are purged; never reuse an old key as a fresh request. A new key represents a new request and may cause another effect if approved.

## 11. Persistence, limits, and operational honesty

SQLite holds owner credentials/session metadata, devices, enrollment invitation hashes, services and encrypted secrets, permissions, requests/results, approvals, and audit metadata. Use foreign keys, uniqueness constraints, and transactions to enforce invariants. Do not hold a database transaction open while making an upstream request. Support one active server instance per database and enforce a startup lock; high availability and rolling multi-instance operation are outside v1.

Audit configuration and decision events in the transaction that changes the corresponding state. Routine audit records contain IDs, safe labels, state transitions, digests, times, and outcomes, never secret values or full request/response bodies. This is a useful local audit history, not a tamper-proof ledger against a compromised server.

Use fixed, documented initial limits instead of a configuration framework: 20 pending approval requests per device, 4 concurrent upstream requests per device, 32 globally, 10-minute approval expiry, 1 MiB stored MCP result limit, and modest enrollment/login/submission throttling. Return explicit overload/size errors. Do not truncate a request body and then approve or execute the truncated version.

For a response exceeding the MCP result limit, preserve a bounded prefix, report `result_truncated`, and never claim a complete result or resend the request. After 24 hours, purge terminal MCP payloads/results while retaining metadata and deduplication tombstones. Pending and executing records are not purged by result retention. Document that retained request/result content can be sensitive even though provider secrets are absent.

Losing the database loses permissions, approvals, and deduplication history. Losing the server unlock secret makes encrypted material unrecoverable. Restoring an old database can resurrect previously valid state: v1 does not support resuming dispatch from a restored backup. A recovery procedure must invalidate device access and undispatched requests before normal service resumes. This limitation is preferable to claiming a safe restore protocol that has not been built.

## 12. Build in five reviewable slices

When the user authorizes implementation of this brief, follow any applicable repository instructions. State each slice and acceptance checks before working; do not silently widen scope. Keep a short progress file so a later agent can resume without conversation history. This document alone does not authorize paid requests, publishing, or accessing real credentials.

### Slice 1: authenticated device to mock upstream

Build the server/SQLite skeleton, encrypted startup state, minimum owner login/setup, service credential entry, invitation enrollment, connector, and one exact standing permission. End-to-end acceptance: an enrolled device reaches a mock upstream, the upstream receives its configured fixture credential, the client does not, and an unenrolled or revoked device cannot dispatch.

This is the first implementation target. Do not build every admin screen or the MCP subsystem before this path works.

### Slice 2: useful standing HTTP gateway

Complete method/path scopes, service revisions, safe header/URL handling, streaming, cancellation, limits, and the generated client configuration. Verify SSE through client + connector + server with deterministic mock tests. Then conduct an explicitly authorized real OpenCode/OpenRouter smoke test if credentials and a spend allowance are available; otherwise report that compatibility check as pending.

### Slice 3: one approved HTTP request through MCP

Add the three tools, immutable submissions, owner inbox/review, approval/denial, durable dispatch, and status/result retrieval. Demonstrate a non-LLM mock service receiving a write only after approval. Prove direct HTTP cannot bypass that route's approval requirement.

### Slice 4: failure semantics and revocation

Test concurrency, duplicate submissions/decisions, expiration, service changes, credential replacement, certificate renewal, revocation on existing connections, and crash recovery. Inject a crash/connection loss around dispatch and prove no automatic resend. Verify that payloads/secrets do not appear in logs or unrelated responses.

### Slice 5: installable portfolio release

Finish the small UI, container packaging, Linux client builds, CI, clean-install documentation, architecture explanation, limitation statement, and a short reproducible demo. Measure stream first-byte overhead, memory during a long stream, and concurrent-request behavior against a direct mock baseline; report the environment and results without invented targets. Publish only when separately authorized.

## 13. Required evidence before calling v1 complete

| Claim | Evidence |
| --- | --- |
| Independent device identity | Two enrolled devices have different scopes; neither can read the other's MCP results; forged identity headers do nothing. |
| Credential custody | Fixture credentials appear only at the configured upstream and trusted setup/storage boundary, never in client responses, generated config, logs, or approval content. A reflected-secret upstream is an explicitly documented exclusion. |
| Standing access | A no-expiry rule survives server restart and remains usable until revoked. Requests outside its method/path scope never reach the upstream. |
| Approval enforcement | No send before approval; direct HTTP receives `approval_required`; modifying any frozen request component cannot reuse the approval. |
| Retry discipline | Concurrent duplicate submissions/approvals/worker wakeups produce at most one automatic dispatch. A crash after dispatch starts yields an uncertain outcome, not a retry. |
| Streaming | The client receives an initial event while the upstream is still open; memory does not grow with total response size; cancellation closes upstream work. |
| Revocation | A new request on an already-open device connection is denied after revocation. A queued request cannot claim dispatch after revocation. |
| Destination confinement | Cross-origin redirects, private/metadata targets, forged Host/forwarding headers, unsupported encodings, and path-boundary tricks cannot widen access. |
| Human identity | Permission and approval records identify the owner; device credentials and CSRF attempts cannot perform owner actions. |
| Honest compatibility | At least one real existing HTTP client and one real MCP host have documented tested versions. Mock-only results are labeled accordingly. |
| Reproducible setup | A fresh operator can start the container, unlock it, enroll a device, configure access, and run the documented demo without access to this conversation. |

Use integration tests for these boundaries and focused unit tests for matching/parsing. Do not pad the project with tests that merely mirror getters, templates, or the implementation's branch structure. CI should build, run relevant tests including Go's race detector, and enforce formatting/static checks.

## 14. Instructions to the implementing agent

Read this document as the proposed product contract. Distinguish existing code, implemented behavior, verified behavior, and future intent in every status report.

Start by inspecting the fresh directory and applicable `AGENTS.md` instructions. Record the first slice and concrete checks. Choose maintained dependency versions from official sources, then implement the smallest complete end-to-end path. Keep crypto, TLS, and MCP on maintained standard libraries/SDKs. Do not write a framework in anticipation of future providers.

If a compatibility issue requires a scope change, explain the concrete conflict and propose the smallest resolution. Do not silently add TLS interception, an OAuth broker, semantic policy evaluation, or a second execution architecture.

Use local mock services and synthetic test data until real integration testing is authorized. Never copy credentials from the old repository or the machine's login stores. Do not change the user's existing working security setup as part of this project.

The finished artifact should be easy to demonstrate and honest to inspect: a small permissioned HTTP gateway with a usable approval path, clearly tested boundaries, and explicit limits.
