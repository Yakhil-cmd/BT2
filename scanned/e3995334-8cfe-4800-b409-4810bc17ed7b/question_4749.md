# Q4749: policy fields default to permissive - buildVerificationPolicy in attestation.go

## Question
Do unset or unparsed policy fields in `buildVerificationPolicy` in [pkg/cmd/release/shared/attestation.go](pkg/cmd/release/shared/attestation.go#L102) default to matching everything (empty string, nil regex, zero value) rather than failing closed?

## Target
- File/function: [pkg/cmd/release/shared/attestation.go:102](pkg/cmd/release/shared/attestation.go#L102) - `buildVerificationPolicy`
- Entrypoint: gh release
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Supply a bundle lacking the extension the policy checks.
- Invariant to test: Missing policy inputs fail closed.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Unit test constructing a policy with zero-value fields asserting no artifact verifies.
