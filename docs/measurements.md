# Mock measurements — 2026-09-10

These are observations, not performance targets or production capacity claims.

Environment: Linux 6.8.0-139-generic, amd64, AMD Ryzen 5 7640HS (6 cores / 12 logical CPUs), Go 1.27.1. Mock upstream, server, connector, SQLite and client all run on this machine inside one Go test process. The benchmark runs without the race detector. Other machine work was not disabled.

Reproduce:

```sh
BUDGE_MEASURE=1 go test ./internal/server -run '^TestMeasureMockGateway$' -count=1 -v -timeout 60s
```

Thirty measured finite SSE requests follow five warmups. The direct client reuses its TLS connection. Budge reuses connector-to-server TLS but deliberately makes a new upstream TLS connection per dispatch to avoid transport replay. First-byte time includes receiving one body byte; the response is then fully drained.

| Observation | Direct TLS mock | Through connector and Budge |
|---|---:|---:|
| Median first byte | 0.063 ms | 3.880 ms |
| 95th percentile first byte | 0.090 ms | 6.699 ms |
| 40 requests, four concurrent callers | 4,932.83 requests/s | 265.45 requests/s |

The observed median added first-byte time was 3.817 ms. These tiny synthetic responses favor the direct baseline; results include local database audit writes and fresh upstream TLS handshakes. They do not measure WAN latency or provider generation.

For a 64 MiB response, combined live Go heap after forced GC was 1,850,312 bytes before streaming, 1,496,696 bytes at 32 MiB, and 1,195,992 bytes afterward. This sample does not show growth with total response size. It is **not peak RSS** and does not isolate server memory. Streaming uses fixed 32 KiB copy buffers, while finite requests are buffered within their size limits. The deterministic streaming test separately proves first-event delivery while the provider stays open and upstream cancellation after the client disconnects.

Concurrency enforcement is a separate integration check: four active requests per device and 32 across eight devices succeed; excess requests are rejected. The throughput measurement is not a substitute for those boundary checks.
