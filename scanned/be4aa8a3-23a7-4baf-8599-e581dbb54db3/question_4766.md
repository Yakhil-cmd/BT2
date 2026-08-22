# Q4766: unauthenticated fallback on error - NewCmdDownload in download.go

## Question
When authentication fails inside `NewCmdDownload` in [pkg/cmd/run/download/download.go](pkg/cmd/run/download/download.go#L39), does it retry unauthenticated (or against a different host) and continue as if it had succeeded?

## Target
- File/function: [pkg/cmd/run/download/download.go:39](pkg/cmd/run/download/download.go#L39) - `NewCmdDownload`
- Entrypoint: gh run download
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Force a 401 from the attacker-controlled host and observe the fallback request.
- Invariant to test: Auth failure aborts; no silent downgrade.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting a single failed request and an error.
