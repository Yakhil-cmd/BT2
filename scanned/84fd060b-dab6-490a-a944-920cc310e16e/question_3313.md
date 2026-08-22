# Q3313: regex catastrophic backtracking - getAttestationDetail in bundle.go

## Question
Can an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims feed a pathological string to the regular expression used in `getAttestationDetail` in [pkg/cmd/attestation/inspect/bundle.go](pkg/cmd/attestation/inspect/bundle.go#L77) causing quadratic/exponential CPU on the victim's machine?

## Target
- File/function: [pkg/cmd/attestation/inspect/bundle.go:77](pkg/cmd/attestation/inspect/bundle.go#L77) - `getAttestationDetail`
- Entrypoint: gh attestation inspect
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Publish a name/body crafted for the specific pattern and let the victim run gh attestation inspect.
- Invariant to test: Patterns are linear-time and inputs are length-capped before matching.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Fuzz/benchmark test asserting bounded runtime on adversarial input.
