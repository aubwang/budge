# Claude Fable review — 2026-09-10

Reviewed commit: `f0912ac036d4fce723fcf08d95feeefe1889aa66`.
Consult job: `job-RYyHvOD-lrk0`; Claude profile, requested model `fable`, confined read-only; completed successfully. Full repository scope. No implementation changes were made.

## Host assessment

The original review follows below unchanged. Its severity labels and conclusions are the reviewer's claims, not blanket host endorsement.

| Finding | Host disposition | Evidence / limitation |
| --- | --- | --- |
| 1. ReadTimeout cuts response streams at 30 seconds (HIGH) | Rejected | Installed Go 1.27.1 `net/http/server.go:731-742` clears the connection read deadline in `startBackgroundRead`. A temporary Go test overlay invoked the actual `cmd/budge.serve` helper with POST bodies consumed before streaming, emitted the first SSE event immediately and the second after 35 seconds. Both plain HTTP and TLS completed with both events and no cancellation, in 35.03 seconds. The overlay was removed; source files were unchanged. This disproves the claimed read-deadline mechanism. It was a focused listener test, not a full provider or container compatibility test. |
| 2. Pre-send transport failures reported as outcome_unknown (LOW) | Supported by code | `internal/server/requests.go:362-366` classifies all Send errors alike, including definite destination/dial rejection from `internal/upstream/http.go`. No resend risk demonstrated; this is inaccurate outcome guidance. Correct classification must remain conservative whenever transmission could have begun. |
| 3. SQLite replacement connections lose PRAGMAs (LOW) | Conditional concern | `internal/store/store.go:54-57` initializes connection-local settings once. No natural production connection replacement was demonstrated. |
| 4. Missing 6to4/Teredo exclusions (LOW) | Unverified hypothesis | Prefixes are absent, but no reachable tunnel configuration, cross-boundary request, or exploit was demonstrated. Do not present this as a verified SSRF bypass. |
| 5. Nonexistent permission/service IDs report successful revocation/disable (LOW) | Supported by code | `internal/server/owner.go:374-407` does not inspect RowsAffected and records success/audit metadata even when no matching record exists. Device revocation does check it. |

Verification performed for this review: static inspection of the cited implementation and installed Go source; targeted 35-second HTTP/TLS tests of the production listener helper, both passed. No full suite rerun, real provider calls, or implementation fixes. Fable itself performed static review only.

## Authorized follow-up fixes — 2026-09-10

Findings 2 and 5 are fixed after the owner's request. `upstream.Send` tags errors as definitely unsent only before Go's `GotConn` trace fires (after dial/TLS and before the request can be written). Durable dispatch records those as `failed/request_not_sent`, keeps later transport failures `outcome_unknown`, and does not retry either state. Permission revocation and service disable now check affected rows and reject nonexistent IDs before recording success or cancelling requests.

Regression tests reproduced both defects before the change and pass afterward. Covered destination rejection, synthetic DNS failure, actual TLS trust failure, pre-send cancellation, duplicate/recovery no-resend behavior, and missing/empty owner-action IDs with unchanged audit history and existing access. Existing post-receipt loss/crash and valid-target cancellation tests remain passing. The full race suite, vet, formatting and diff checks pass. Findings 1, 3 and 4 retain the dispositions above; no broader architecture change was made.

## Original Consult output

I'll start by reading the required documentation, then inspect the implementation.# Review: fresh Budge at f0912ac

I read AGENTS.md, BUILD_HANDOFF.md, DESIGN.md, docs/progress.md and docs/verification.md, then every Go source file, migration, template/JS asset, test, script, the Dockerfile/compose/CI definitions, and the operator docs. The old Budge repository was not touched. Overall this is an unusually tight implementation: the authorization, approval/digest, dedup, revocation, SSRF, crypto, and crash-recovery boundaries all held up under adversarial reading, and the test suite genuinely exercises the boundaries it claims (real TLS hops, real MCP stdio subprocess, real process kill). I found one significant correctness defect and a handful of smaller items.

---

## Finding 1 — HIGH: `ReadTimeout: 30s` in the packaged binary terminates streaming responses at ~30 seconds (contradicts the streaming contract and the documented 5-minute idle timeout)

**Supported** (code plus documented `net/http` semantics; recommend one targeted host validation, below).

**Where:** `cmd/budge/main.go:271`

```go
s := &http.Server{Handler: handlers[i], ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, IdleTimeout: time.Minute, ...}
```

This one `serve()` helper builds the HTTP servers for **all** listeners: the device TLS listener, the owner listener, the connector's loopback listener, and the connector's Unix socket (`cmd/budge/main.go:136`, `241`).

**Mechanism:** `http.Server.ReadTimeout` arms an absolute read deadline at request start (t0+30s). Once the handler has consumed the request body, `net/http` starts a background read on the connection to detect client disconnect. When the 30-second deadline expires during a still-streaming response, that background read fails with a timeout, and `connReader.handleReadError` **cancels the request context**. In `DeviceHandler` the upstream request is created with `r.Context()` (`internal/server/server.go:205`), so the upstream SSE fetch is aborted and the stream is severed. The same happens independently at the connector hop (`internal/client/client.go:212` uses `r.Context()`), so any standing streaming response longer than ~30 seconds — precisely the OpenRouter chat-completion flagship use case — is killed mid-generation in the packaged deployment. It also caps slow 8 MiB uploads at 30 seconds end-to-end.

**Why the verification record doesn't show it:** every streaming test (`TestSlice2StreamingCancellationAndLimits`, `TestMeasureMockGateway`) builds servers via `httptest`, which sets no timeouts, and the container smoke test never streams longer than 30 seconds. So the Slice-2 "progressive SSE, cancellation" evidence is true of the test harness but not of the shipped `serve()` path. This directly conflicts with BUILD_HANDOFF.md §8 ("do not … impose a short total timeout that breaks ordinary generation. Use bounded connection/header timeouts and a documented generous stream-idle timeout", line 204), with README.md:43 ("a five-minute stream-idle timeout" — the 5-minute rolling `IdleConn` read deadline in `internal/upstream/http.go:113` never gets a chance to matter), and with docs/verification.md's streaming row as it applies to the packaged binary.

**Triggering scenario:** operator deploys via compose, grants standing `POST /v1/chat/completions`, OpenCode requests a generation that streams for >30s → the stream dies at ~30s at whichever hop's deadline fires first; the client sees a truncated response.

**Minimal correction:** remove `ReadTimeout` from the device and connector listeners (keep `ReadHeaderTimeout: 10s`; if a bounded request-read window is wanted, set a per-request read deadline via `http.NewResponseController.SetReadDeadline` after the body is consumed, extending it for streaming handlers). The owner listener can keep `ReadTimeout` if desired.

**Suggested host validation:** run the real binary (`serve()` path, not httptest) against a mock that emits an SSE event, sleeps 35 s, then emits another; observe the stream terminate at ~30 s.

---

## Finding 2 — LOW: every MCP dispatch transport error becomes `outcome_unknown`, including definite pre-send local failures

**Supported.**

**Where:** `internal/server/requests.go:362-366`

```go
res, e := upstream.Send(ctx, svc, snap.Method, snap.URL, snap.Headers, strings.NewReader(snap.Body), secret, tr)
if e != nil {
    s.finish(id, "outcome_unknown", "connection_lost_check_provider", nil)
    return
}
```

A DNS resolution failure, a blocked destination (`"destination blocked"` from the dialer), or a TLS handshake failure all occur before any request bytes could have been transmitted, yet the request is finished as `outcome_unknown` with guidance to "check the provider," and it permanently consumes its single dispatch attempt. BUILD_HANDOFF §10 (line 268) reserves `failed` for exactly this case ("rejection before sending"). The conservative direction is safe (never triggers a resend), but it misleads the owner and agent — e.g., an approved request against a service whose DNS is temporarily broken reports "the upstream may have performed this request," forcing a needless provider audit plus a fresh submission/approval cycle. Note the standing HTTP path already distinguishes this correctly (502 `upstream_unavailable`, `internal/server/server.go:206-209`), and shutdown-context cancellation before `Send` begins lands in the same over-broad bucket.

**Minimal correction:** classify errors that provably occur before the request is written — dial/resolve/handshake failures (e.g., wrap the dialer's errors in a sentinel type, or check `errors.As(&net.OpError{})` with `Op == "dial"`) — as `failed` with a local reason; keep `outcome_unknown` for everything after the connection is established.

---

## Finding 3 — LOW: per-connection SQLite PRAGMAs can be silently lost if the pooled connection is replaced

**Hypothesis** (correct as code reading; the triggering condition is rare).

**Where:** `internal/store/store.go:54-57`

```go
s.DB.SetMaxOpenConns(1)
if _, err = s.DB.Exec("PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;"); err != nil {
```

`foreign_keys` and `busy_timeout` are per-connection settings executed once on whatever connection the pool hands out. If `database/sql` ever discards that connection (driver returns `ErrBadConn`, connection error) and opens a new one, the replacement runs with foreign keys **off** and no busy timeout, silently weakening the referential invariants the schema relies on (`journal_mode=WAL` is persistent and unaffected). Migrations also run before these PRAGMAs, which is currently harmless.

**Minimal correction:** move the PRAGMAs into the DSN so every connection gets them: `sql.Open("sqlite", path+"?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")` (supported by modernc.org/sqlite), keeping the WAL statement or adding it to the DSN as well.

---

## Finding 4 — LOW: SSRF address filter omits 6to4/Teredo IPv6 prefixes

**Hypothesis** (requires an uncommon host configuration to exploit).

**Where:** `internal/upstream/http.go:71`

```go
for _, raw := range []string{"100.64.0.0/10", "192.0.0.0/24", "198.18.0.0/15", "240.0.0.4", "64:ff9b::/96", "64:ff9b:1::/48"} { ... }
```

(The actual list is `"240.0.0.0/4"` — the block list covers shared/reserved space and NAT64, matching DESIGN.md's "IPv4 translation prefixes" claim.) It does not cover 6to4 `2002::/16` or Teredo `2001::/32`, which embed IPv4 addresses; on a host with 6to4/Teredo routing, a hostile DNS answer of e.g. `2002:7f00:1::` could reach tunneled private/loopback space. Exploitation needs the owner to configure a service at an attacker-influenced hostname *and* the trusted machine to route those tunnels — both unusual. Since the design explicitly enumerates translation prefixes, completing the set is cheap.

**Minimal correction:** add `2002::/16` and `2001::/32` (Teredo; the broader `2001::/23` IETF-reserved block if preferred) to the reserved list.

**Not a finding, for the record:** the rest of the confinement is done right — all resolved answers are checked, the dial goes to the validated IP with the TLS ServerName preserved (no rebinding TOCTOU), redirects are disabled at every hop, and the private-CIDR exception cannot cover link-local/metadata (`CIDR` requires `IsPrivate()`).

---

## Finding 5 — LOW: `revokePermission` and `disableService` report success for nonexistent IDs

**Supported.**

**Where:** `internal/server/owner.go:374-390` and `391-407`. Both run `UPDATE ... WHERE id=?` without checking `RowsAffected` (unlike `revoke` for devices, which does at `owner.go:419-422`), then write an audit row for the possibly nonexistent entity and redirect as if the revocation succeeded. With UI-driven POSTs the ID is normally valid, so this is a consistency/robustness issue rather than an exploitable one — but a mistyped or stale ID in a scripted revocation would silently no-op while the audit log records `permission_revoked`.

**Minimal correction:** check `RowsAffected` and return an error when zero, as `revoke` already does.

---

## Informational notes (no action strictly required)

- **Owner login lockout:** the login throttle key is global (`s.throttle("login", 10)`, `internal/server/owner.go:139`), so any local process able to reach the loopback owner port can exhaust the 10/min budget and lock the owner out. Loopback-only exposure makes this minor; a per-source or exponential backoff scheme would remove it.
- **Approved requests can expire under slot saturation:** `RunWorker` skips a queued request when `acquire` fails (`internal/server/requests.go:301-307`); a device holding its 4 standing streams for the full 10-minute approval window causes an approved request to end `expired/deadline_elapsed`. This is contract-consistent ("expiry for an approved request is the original approval deadline") but worth knowing operationally.
- **`outcome_unknown` on SIGTERM before transmission** is a special case of Finding 2 (worker context cancellation aborts `Send`, which may not have connected yet).

## What I specifically checked and found sound

Authorization default-deny and overlap rejection (transactionally serialized via the single-connection pool); revision invalidation and cancellation with reasons; approval digest binding at both decision and claim time plus snapshot cross-field integrity (`snapshot`/`validSnapshot`); single-claim discipline (status-guarded claim inside serialized transactions, no `GetBody`, fresh HTTP/1 no-keep-alive transport per dispatch, `dispatching`→`outcome_unknown` on restart); dedup semantics including tombstones after purge; per-request revocation/expiry checks on live TLS connections; CSR handling (server-assigned identity, no extension copying, client-auth EKU separation from the server leaf); credential purpose-bound AES-GCM with Argon2id and no read-back path; reserved-header stripping on both hops including `Connection`-nominated and method-override headers; conservative path grammar (percent-escapes rejected via `RawPath`, dot segments, `//`); owner Host/Origin/Sec-Fetch/CSRF/session handling and fully escaped templates (no `template.HTML` anywhere; the invitation and review pages are safe); connector browser-rejection; socket ownership/mode checks; container packaging (nonroot, read-only, loopback publication, pinned bases/actions, binaries untracked); and the smoke/demo scripts doing what the docs claim.

## Coverage and limitations

I read every file in the repository at f0912ac (all ~4.8k lines of Go, migrations, web assets, scripts, CI, and docs). Per the review constraints I did **not** run tests, builds, or the container smoke, so: (a) Finding 1 rests on well-documented Go `net/http` behavior rather than a live reproduction — the suggested >30s stream check through the packaged binary would confirm it; (b) I could not verify dependency authenticity (go.sum contents, the pinned image digests, the claimed Go 1.27.1/MCP SDK v1.7.0/curl 8.5.0/OpenCode 1.18.20 versions) beyond internal consistency; (c) the measurement numbers in docs/measurements.md are taken on trust as labeled observations; (d) MCP SDK behaviors (unknown-argument rejection, stdout discipline) are covered by the repo's own tests rather than independent inspection of the SDK. The documentation's claims otherwise matched the code everywhere I checked, with the single material exception being the streaming-timeout discrepancy in Finding 1.
