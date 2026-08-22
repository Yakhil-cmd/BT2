# Q4748: nil dereference panic on hostile field - FilterAttestationsByFileDigest in attestation.go

## Question
Can an attacker-shaped response make `FilterAttestationsByFileDigest` in [pkg/cmd/release/shared/attestation.go](pkg/cmd/release/shared/attestation.go#L76) dereference a nil pointer or index out of range, crashing gh mid-operation (leaving partial state on disk)?

## Target
- File/function: [pkg/cmd/release/shared/attestation.go:76](pkg/cmd/release/shared/attestation.go#L76) - `FilterAttestationsByFileDigest`
- Entrypoint: gh release
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Return a response with nested nulls or empty arrays where gh expects data.
- Invariant to test: All response-derived structures are checked before dereference.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Fuzz the decoder with mutated payloads asserting no panic.
