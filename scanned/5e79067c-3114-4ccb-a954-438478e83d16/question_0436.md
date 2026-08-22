# Q0436: host-scoped client leaked into another flow - shouldRetry in client.go

## Question
Can the client/transport constructed in `shouldRetry` in [pkg/cmd/attestation/api/client.go](pkg/cmd/attestation/api/client.go#L282) (with its auth round-tripper) be reused by a later flow whose target host came from an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims?

## Target
- File/function: [pkg/cmd/attestation/api/client.go:282](pkg/cmd/attestation/api/client.go#L282) - `shouldRetry`
- Entrypoint: gh attestation
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Chain two operations where the second targets an attacker host.
- Invariant to test: Auth round-trippers verify the request host on every call.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test reusing the client against a foreign host asserting the header is dropped.
