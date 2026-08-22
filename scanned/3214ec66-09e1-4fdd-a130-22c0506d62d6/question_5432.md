# Q5432: unauthenticated fallback on error - shouldRetry in client.go

## Question
When authentication fails inside `shouldRetry` in [pkg/cmd/attestation/api/client.go](pkg/cmd/attestation/api/client.go#L282), does it retry unauthenticated (or against a different host) and continue as if it had succeeded?

## Target
- File/function: [pkg/cmd/attestation/api/client.go:282](pkg/cmd/attestation/api/client.go#L282) - `shouldRetry`
- Entrypoint: gh attestation
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Force a 401 from the attacker-controlled host and observe the fallback request.
- Invariant to test: Auth failure aborts; no silent downgrade.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting a single failed request and an error.
