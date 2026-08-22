# Q1166: cached response written world-readable - NewTrustedRootCmd in trustedroot.go

## Question
Does the on-disk cache used by `NewTrustedRootCmd` in [pkg/cmd/attestation/trustedroot/trustedroot.go](pkg/cmd/attestation/trustedroot/trustedroot.go#L33) store authenticated response bodies (including private data) with permissive modes or predictable names in a shared directory?

## Target
- File/function: [pkg/cmd/attestation/trustedroot/trustedroot.go:33](pkg/cmd/attestation/trustedroot/trustedroot.go#L33) - `NewTrustedRootCmd`
- Entrypoint: gh attestation trustedroot
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Read another user's gh cache on a shared build host.
- Invariant to test: Cache files live in the user's private dir with 0600.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Test asserting cache file mode and location.
