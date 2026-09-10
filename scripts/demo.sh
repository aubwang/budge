#!/usr/bin/env sh
set -eu
printf '%s\n' 'Budge mock demo: enrollment and standing HTTP, then an approved non-LLM write over MCP.'
go test ./internal/server -run '^(TestSlice1AuthenticatedRoundTrip|TestSlice2StreamingCancellationAndLimits|TestSlice3MCPApprovalRoundTrip|TestSlice4RealProcessCrashAfterTransmission|TestExistingCurlClient)$' -v -count=1 -timeout 60s
printf '%s\n' 'Demo completed using disposable databases, synthetic credentials, and local TLS mocks only.'
