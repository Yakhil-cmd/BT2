# Q1144: error body echoed verbatim - NewLiveClient in client.go

## Question
Does the error construction in `NewLiveClient` in [pkg/cmd/attestation/api/client.go](pkg/cmd/attestation/api/client.go#L78) embed the attacker-controlled response body or headers into a message that is printed or sent to telemetry?

## Target
- File/function: [pkg/cmd/attestation/api/client.go:78](pkg/cmd/attestation/api/client.go#L78) - `NewLiveClient`
- Entrypoint: gh attestation
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Return an error body containing escapes or fabricated gh output.
- Invariant to test: Server-supplied error text is sanitized and length-bounded before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test of the error string for a hostile body.
