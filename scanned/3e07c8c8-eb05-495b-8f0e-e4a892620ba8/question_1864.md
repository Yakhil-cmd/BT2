# Q1864: cached response written world-readable - shouldRetry in client.go

## Question
Does the on-disk cache used by `shouldRetry` in [pkg/cmd/attestation/api/client.go](pkg/cmd/attestation/api/client.go#L282) store authenticated response bodies (including private data) with permissive modes or predictable names in a shared directory?

## Target
- File/function: [pkg/cmd/attestation/api/client.go:282](pkg/cmd/attestation/api/client.go#L282) - `shouldRetry`
- Entrypoint: gh attestation
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Read another user's gh cache on a shared build host.
- Invariant to test: Cache files live in the user's private dir with 0600.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Test asserting cache file mode and location.
