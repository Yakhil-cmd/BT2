# Q1823: retry amplification - runVerify in verify.go

## Question
Can an attacker-controlled endpoint reached from `runVerify` in [pkg/cmd/attestation/verify/verify.go](pkg/cmd/attestation/verify/verify.go#L264) return statuses that drive unbounded retries or recursion (redirect loop, 429 with a huge Retry-After, endless pagination)?

## Target
- File/function: [pkg/cmd/attestation/verify/verify.go:264](pkg/cmd/attestation/verify/verify.go#L264) - `runVerify`
- Entrypoint: gh attestation verify
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Serve a response that always asks for another page or retry.
- Invariant to test: Retries and pagination are bounded by explicit counters.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Test with an endless-pagination server asserting a bounded number of requests.
