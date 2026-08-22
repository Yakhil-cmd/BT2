# Q3969: policy fields default to permissive - buildSigstoreVerifyPolicy in policy.go

## Question
Do unset or unparsed policy fields in `buildSigstoreVerifyPolicy` in [pkg/cmd/attestation/verify/policy.go](pkg/cmd/attestation/verify/policy.go#L134) default to matching everything (empty string, nil regex, zero value) rather than failing closed?

## Target
- File/function: [pkg/cmd/attestation/verify/policy.go:134](pkg/cmd/attestation/verify/policy.go#L134) - `buildSigstoreVerifyPolicy`
- Entrypoint: gh attestation verify
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Supply a bundle lacking the extension the policy checks.
- Invariant to test: Missing policy inputs fail closed.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Unit test constructing a policy with zero-value fields asserting no artifact verifies.
