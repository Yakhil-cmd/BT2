# Q0465: regex catastrophic backtracking - FilterAttestationsByFileDigest in attestation.go

## Question
Can an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims feed a pathological string to the regular expression used in `FilterAttestationsByFileDigest` in [pkg/cmd/release/shared/attestation.go](pkg/cmd/release/shared/attestation.go#L76) causing quadratic/exponential CPU on the victim's machine?

## Target
- File/function: [pkg/cmd/release/shared/attestation.go:76](pkg/cmd/release/shared/attestation.go#L76) - `FilterAttestationsByFileDigest`
- Entrypoint: gh release
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Publish a name/body crafted for the specific pattern and let the victim run gh release.
- Invariant to test: Patterns are linear-time and inputs are length-capped before matching.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Fuzz/benchmark test asserting bounded runtime on adversarial input.
