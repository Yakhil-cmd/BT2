# Q2603: cached response written world-readable - verifyRun in verify.go

## Question
Does the on-disk cache used by `verifyRun` in [pkg/cmd/release/verify/verify.go](pkg/cmd/release/verify/verify.go#L118) store authenticated response bodies (including private data) with permissive modes or predictable names in a shared directory?

## Target
- File/function: [pkg/cmd/release/verify/verify.go:118](pkg/cmd/release/verify/verify.go#L118) - `verifyRun`
- Entrypoint: gh release verify
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Read another user's gh cache on a shared build host.
- Invariant to test: Cache files live in the user's private dir with 0600.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Test asserting cache file mode and location.
