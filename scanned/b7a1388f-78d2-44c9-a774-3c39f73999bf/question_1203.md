# Q1203: unauthenticated fallback on error - populateLogSegments in logs.go

## Question
When authentication fails inside `populateLogSegments` in [pkg/cmd/run/view/logs.go](pkg/cmd/run/view/logs.go#L95), does it retry unauthenticated (or against a different host) and continue as if it had succeeded?

## Target
- File/function: [pkg/cmd/run/view/logs.go:95](pkg/cmd/run/view/logs.go#L95) - `populateLogSegments`
- Entrypoint: gh run view
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Force a 401 from the attacker-controlled host and observe the fallback request.
- Invariant to test: Auth failure aborts; no silent downgrade.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting a single failed request and an error.
