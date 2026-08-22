# Q4745: numeric overflow / negative length - printVerifiedSubjects in verify.go

## Question
Does `printVerifiedSubjects` in [pkg/cmd/release/verify/verify.go](pkg/cmd/release/verify/verify.go#L196) use a size/count/index from remote data in arithmetic or allocation without range checks?

## Target
- File/function: [pkg/cmd/release/verify/verify.go:196](pkg/cmd/release/verify/verify.go#L196) - `printVerifiedSubjects`
- Entrypoint: gh release verify
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Return a huge or negative numeric field.
- Invariant to test: Remote numerics are range-checked before allocation or slicing.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Table test with extreme values asserting an error.
