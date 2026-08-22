# Q0460: unauthenticated fallback on error - NewCmdVerify in verify.go

## Question
When authentication fails inside `NewCmdVerify` in [pkg/cmd/release/verify/verify.go](pkg/cmd/release/verify/verify.go#L40), does it retry unauthenticated (or against a different host) and continue as if it had succeeded?

## Target
- File/function: [pkg/cmd/release/verify/verify.go:40](pkg/cmd/release/verify/verify.go#L40) - `NewCmdVerify`
- Entrypoint: gh release verify
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Force a 401 from the attacker-controlled host and observe the fallback request.
- Invariant to test: Auth failure aborts; no silent downgrade.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting a single failed request and an error.
