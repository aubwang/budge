# Start and demonstrate Budge

All examples are for Linux. Use a trusted machine for the server. The first demo uses synthetic data only and does not need provider credentials or a paid account.

## Reproducible mock demo

With Go 1.27.1 and curl installed:

```sh
scripts/build-linux.sh
scripts/demo.sh
```

The demo creates temporary SQLite databases, a trusted TLS mock, an owner session and an enrolled connector. It verifies ordinary HTTP, progressive SSE/cancellation, an approved non-LLM write through MCP, and an interrupted dispatch that is never resent. It cleans up its listeners and temporary state. The mock destination exception exists only in test code; it cannot be enabled in the shipped binary.

For a disposable clean install of the actual container/client, run:

```sh
docker build -t budge-fresh:local .
python3 scripts/smoke-container.py
```

This uses a uniquely named temporary container/volume, synthetic passwords through hidden terminal prompts, and the built Linux client. It checks owner login, one-use enrollment, encrypted device storage, connector identity, default deny, private socket mode, loopback publication and absence of setup secrets in logs. Its container and volume are removed afterward.

## Start a persistent server

```sh
docker compose build
docker compose run --rm --service-ports budge
```

This command runs in the foreground and attaches a terminal. At first startup, enter a server unlock secret and a separate owner password (at least 12 characters each). They are hidden while typed. Open `http://127.0.0.1:8080` and sign in. On later starts, only the unlock secret is required. Interrupting the container stops service; its named data volume remains. Do not use `docker compose down -v` unless you intend to destroy that state.

The default composition publishes both ports only on host loopback, suitable for trying setup locally. To use a remote device, select the externally reachable HTTPS hostname/IP with `server --url`, change the device port publication to the desired trusted-machine address, and set `--device-listen 0.0.0.0:8443` inside the container. Configure this URL on the initial start; it is part of the stored server identity. Keep the owner publication **127.0.0.1:8080:8080** and the expected owner Host **127.0.0.1:8080**. The default command in Dockerfile shows all server arguments.

The `--container` flag permits the internal owner bind on 0.0.0.0. It does not make external publication safe. Host-port publication and network reachability are operator responsibilities. The shipped Compose file keeps the owner port on loopback. Network access can additionally be restricted with a VPN/firewall; it never substitutes for device enrollment.

For remote administration, tunnel the owner port to the same local port using SSH, then browse `http://127.0.0.1:8080`. Host and Origin must match the configured owner address. No device certificate or approval URL grants owner access.

## Configure a service and device

1. In the owner UI, create a service with a lowercase ID, account label and fixed HTTPS base URL. Choose `none`, `bearer`, `header`, or `basic`. Credentials are write only. For basic authentication, enter `username:password`. For header auth, select a nonreserved header such as `X-API-Key`.
2. Start with `Accept, Content-Type` as request headers and `Content-Type, Content-Encoding, Retry-After` as response headers. Add application headers explicitly. Reserved authentication, cookie, forwarding, identity and hop-by-hop headers cannot be enabled.
3. If the intended destination is private, specify its private CIDR. Loopback and link-local/metadata destinations stay blocked. DNS answers and HTTPS certificates are checked at connection time.
4. Create a device invitation. Transfer it privately; it works once for five minutes. Do not put it in shell arguments, screenshots, logs or notes.
5. On the device, run `budge-linux-amd64 enroll` (or the arm64 binary), paste the invitation at the hidden prompt, and choose an identity passphrase. The default identity file is under the user's config directory in `budge/device.identity`, encrypted and mode 0600.
6. Back in the UI, grant an explicit method list and exact/subtree path. Choose standing or approval-required access. Blank expiry means until revoked. Overlap with an existing active scope is rejected. Query values and body fields remain unrestricted.
7. Run `budge-linux-amd64 connect`, unlock it, and use `http://127.0.0.1:7777/s/SERVICE/PATH`. All local processes able to reach the connector share that device's access.

A service replacement increments its revision, including credential or header changes. Existing permissions become obsolete; review and explicitly reissue them. Re-enter the credential when replacing a service. Revocation and replacement cancel pending/queued requests but cannot retract a dispatch already claimed.

## OpenCode provider configuration

For a service named `openrouter` with base URL `https://openrouter.ai/api`, grant `POST /v1/chat/completions`. Generate the routing fragment:

```sh
budge-linux-amd64 connect --print-opencode-config
```

It supplies `provider.openrouter.options.baseURL` as `http://127.0.0.1:7777/s/openrouter/v1` and `apiKey` as the nonsecret placeholder `budge-local`. Merge only this routing fragment into an isolated client configuration when performing an authorized compatibility test. No body transformation occurs. These fields were checked against [OpenCode's provider documentation](https://opencode.ai/docs/providers/) and loaded by OpenCode 1.18.20 in isolated settings; the real OpenRouter generation smoke test is still pending. Do not copy provider secrets into the agent's config.

## MCP

Keep the connector running, then configure the host to launch the same binary's `mcp` subcommand. For OpenCode:

```json
{
  "mcp": {
    "budge": {
      "type": "local",
      "command": ["/absolute/path/to/budge-linux-amd64", "mcp"],
      "enabled": true
    }
  }
}
```

If using a custom connector socket, add `--socket /absolute/private/connect.sock` to both connector and MCP commands. The socket directory must be user-owned mode 0700, and its socket is mode 0600. If a crash leaves a stale socket, first confirm no connector is running before removing that socket. No credentials are read from MCP protocol streams; diagnostics use stderr.

The host sees three tools. `budge_services` lists authorized scopes. `budge_request` submits `service`, `method`, `path`, optional raw `query`, optional string-valued `headers`, a UTF-8 `body`, and a required client-generated `idempotency_key`. The body limit is 64 KiB. Unknown arguments are rejected. Use `budge_request_status` with the returned `request_id`; `wait_seconds` may be 0–15. Do not resubmit with a new key merely because approval is pending.

Review the actual URL/query, headers, body, expiry and digest in the owner inbox. Approve or deny there. The owner cannot edit the stored request. The result cap applies to the first 1 MiB of upstream body bytes; base64/envelope overhead is additional. Binary or heavily escaped text is represented as base64. Upstream response headers are capped at 32 KiB. Complete upstream 4xx/5xx responses remain HTTP results; they are not retried. `outcome_unknown` means check the provider before considering another request.

## Operations and recovery

Unlock inputs may come from dedicated file descriptors (`--unlock-fd`, `--owner-password-fd`, `--invitation-fd`, `--passphrase-fd`) rather than a terminal. Each descriptor supplies one line; its numeric FD is a flag, the secret value is not. Supply runtime pipes from your chosen secret manager, never `.env` files, container environment variables, image layers or adjacent plaintext files. No unattended-start promise is made.

Client certificates renew during their final seven days. The identity file is replaced atomically while remaining encrypted. Expired/revoked devices require a new invitation. Trust-root replacement requires re-enrollment. Losing the server unlock secret makes encrypted data unrecoverable; losing the owner password is a separate account-recovery issue and no self-service password-reset flow is provided in v1.

Do not resume normal service from a restored database. Before traffic, start it with `server --recover-restored` plus the usual deployment arguments. This invalidates all old devices and owner sessions and cancels undispatched requests. Reconcile provider effects, then enroll devices and reissue access deliberately. Old backups can lack deduplication keys; Budge cannot reconstruct them. Do not infer safe retry from an absent record.

See README.md for limits, DESIGN.md for trust boundaries and docs/verification.md for precise evidence and outstanding decisions.
