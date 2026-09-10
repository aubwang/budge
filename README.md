# Budge

Configure an HTTP service on a trusted machine, enroll a device, and grant it specific access without giving it the upstream credential.

Budge is one Go binary: a server with SQLite and a small owner UI, a local connector, enrollment, and an MCP stdio adapter. Ordinary HTTP clients use standing permissions by changing their base URL. Requests needing individual approval use MCP and remain pending until the owner reviews the actual HTTP request.

**Status:** all five implementation slices are implemented and verified locally against synthetic TLS mocks. curl 8.5.0 completed an HTTP round trip; OpenCode 1.18.20 connected as an MCP host. Real OpenCode/OpenRouter generation remains untested and requires separate authorization. Nothing is published.

## Try the mock demo

Requires Go 1.27.1 and curl; no provider account or real credentials:

```sh
scripts/build-linux.sh
scripts/demo.sh
```

For the actual container/client clean-install check, with Docker and Python 3:

```sh
docker build -t budge-fresh:local .
python3 scripts/smoke-container.py
```

The tests use disposable state and synthetic inputs. The packaged server has no test-only loopback-upstream bypass.

## Start a server

```sh
docker compose build
docker compose run --rm --service-ports budge
```

Enter a server unlock secret and a separate initial owner password at the hidden prompts. Open `http://127.0.0.1:8080`. Create a service and invitation; enroll a device with `budge enroll`, grant its scope in the UI, then run `budge connect` on the device. An ordinary client uses `http://127.0.0.1:7777/s/SERVICE/PATH`. MCP hosts launch `budge mcp` while the connector is running.

The default composition publishes both ports on loopback. The [operator guide](docs/operator-guide.md) explains remote devices, SSH administration, encrypted identity files, dedicated secret input streams, OpenCode configuration, and recovery. Server and connector require unlocking after restart; there is no unattended-start promise.

## Access and limits

- Permissions bind an owner, device, service revision, explicit methods, exact/segment-subtree path, standing/approval-required mode and optional expiry. Overlapping active scopes are rejected. Service or credential changes invalidate old permissions.
- Upstream authentication supports none, bearer, a selected header, and basic. Credentials, TLS keys and stored MCP content are encrypted with authenticated encryption. Credentials are write only in owner controls.
- Fixed HTTPS destinations, connection-time address checks, standard certificate validation, reserved-header removal and no redirects/proxies confine dispatch. Private targets require an explicit CIDR; loopback/link-local/metadata stay blocked.
- HTTP bodies are finite and at most 8 MiB. Responses stream, including SSE. Budge permits four concurrent upstream requests per device and 32 globally, with a five-minute stream-idle timeout.
- MCP bodies are UTF-8 and at most 64 KiB. There are 20 pending approvals per device, a ten-minute approval deadline, a one-minute standing queue deadline, a two-minute finite dispatch deadline, and a 1 MiB stored result limit. Terminal payloads are purged after 24 hours; deduplication tombstones remain.
- Durable requests receive one automatic dispatch attempt. Connection loss or a crash may mean the provider performed the effect; `outcome_unknown` is never automatically retried. This is not exactly-once execution.

Paths use a conservative ASCII grammar: one leading slash, no escapes, backslashes, empty interior segments, or dot segments. Exact trailing slashes remain distinct. Query/body values are unrestricted by permissions; Budge does not enforce recipients, models, spending, or intent. Local processes share the connector's device authority. An upstream that reflects its own credential can expose it; Budge is not a response DLP filter.

## Inspect and develop

```sh
go test -race ./... -timeout 120s
go vet ./...
go build -o bin/budge ./cmd/budge
```

The design contract is [BUILD_HANDOFF.md](BUILD_HANDOFF.md); no old Budge implementation was imported. Read [architecture and trust boundaries](DESIGN.md), [verification evidence and remaining decisions](docs/verification.md), [measured mock performance](docs/measurements.md), and [progress notes](docs/progress.md).

Dependencies are pinned in go.mod/go.sum: [modernc SQLite](https://pkg.go.dev/modernc.org/sqlite@v1.58.0), [official MCP Go SDK](https://github.com/modelcontextprotocol/go-sdk/tree/v1.7.0), and Go's maintained crypto/terminal modules. CI runs formatting, vet, race tests, Linux builds, image build and disposable setup checks. The initial development box's checksum-verified Go toolchain is under `~/.local/share/budge-toolchain/go/bin`.
