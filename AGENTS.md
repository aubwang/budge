# Fresh Budge

Read BUILD_HANDOFF.md and docs/progress.md before implementation. BUILD_HANDOFF.md is the fixed product contract. Do not import the old Budge implementation.

Work through its five slices in order. State acceptance checks before each slice, verify them, and update docs/progress.md. The user authorized autonomous work until a major decision needs input. Use mock upstreams and synthetic credentials only; real integrations, spending, and publishing need separate authorization.

Use Go, SQLite, standard TLS/crypto, and the official MCP Go SDK when Slice 3 begins. Keep one binary and one server/database. Do not add frameworks or broaden scope to resolve a compatibility issue without surfacing it.

Run gofmt, go vet, and relevant tests (including race checks at slice boundaries). Keep runtime databases, keys, unlock material, binaries, and local tool caches out of git. Never log request bodies, queries, credentials, invitations, or sensitive paths.

Owner clarification: keep the runtime CLI and HTTP routing client-independent. Client-specific configuration examples belong in documentation and compatibility tests, not dedicated CLI flags. Current default ports are 18780 (owner), 18781 (device TLS), and 18782 (local connector); these supersede the original handoff's example ports. Keep CLI defaults, container packaging and current operator instructions consistent.
