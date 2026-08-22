# Q1893: retry amplification - FilterAttestationsByFileDigest in attestation.go

## Question
Can an attacker-controlled endpoint reached from `FilterAttestationsByFileDigest` in [pkg/cmd/release/shared/attestation.go](pkg/cmd/release/shared/attestation.go#L76) return statuses that drive unbounded retries or recursion (redirect loop, 429 with a huge Retry-After, endless pagination)?

## Target
- File/function: [pkg/cmd/release/shared/attestation.go:76](pkg/cmd/release/shared/attestation.go#L76) - `FilterAttestationsByFileDigest`
- Entrypoint: gh release
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Serve a response that always asks for another page or retry.
- Invariant to test: Retries and pagination are bounded by explicit counters.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Test with an endless-pagination server asserting a bounded number of requests.
