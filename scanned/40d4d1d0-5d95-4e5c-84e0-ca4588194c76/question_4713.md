# Q4713: cached response written world-readable - NewLiveClient in client.go

## Question
Does the on-disk cache used by `NewLiveClient` in [pkg/cmd/attestation/api/client.go](pkg/cmd/attestation/api/client.go#L78) store authenticated response bodies (including private data) with permissive modes or predictable names in a shared directory?

## Target
- File/function: [pkg/cmd/attestation/api/client.go:78](pkg/cmd/attestation/api/client.go#L78) - `NewLiveClient`
- Entrypoint: gh attestation
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Read another user's gh cache on a shared build host.
- Invariant to test: Cache files live in the user's private dir with 0600.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Test asserting cache file mode and location.
