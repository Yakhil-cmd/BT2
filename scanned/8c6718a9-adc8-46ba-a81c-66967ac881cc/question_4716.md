# Q4716: retry amplification - (LiveClient).getAttestations in client.go

## Question
Can an attacker-controlled endpoint reached from `getAttestations` in [pkg/cmd/attestation/api/client.go](pkg/cmd/attestation/api/client.go#L142) return statuses that drive unbounded retries or recursion (redirect loop, 429 with a huge Retry-After, endless pagination)?

## Target
- File/function: [pkg/cmd/attestation/api/client.go:142](pkg/cmd/attestation/api/client.go#L142) - `(LiveClient).getAttestations`
- Entrypoint: gh attestation
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Serve a response that always asks for another page or retry.
- Invariant to test: Retries and pagination are bounded by explicit counters.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Test with an endless-pagination server asserting a bounded number of requests.
