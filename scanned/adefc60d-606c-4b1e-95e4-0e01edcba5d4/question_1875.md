# Q1875: policy fields default to permissive - IsValidDigestAlgorithm in digest.go

## Question
Do unset or unparsed policy fields in `IsValidDigestAlgorithm` in [pkg/cmd/attestation/artifact/digest/digest.go](pkg/cmd/attestation/artifact/digest/digest.go#L23) default to matching everything (empty string, nil regex, zero value) rather than failing closed?

## Target
- File/function: [pkg/cmd/attestation/artifact/digest/digest.go:23](pkg/cmd/attestation/artifact/digest/digest.go#L23) - `IsValidDigestAlgorithm`
- Entrypoint: gh attestation
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Supply a bundle lacking the extension the policy checks.
- Invariant to test: Missing policy inputs fail closed.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Unit test constructing a policy with zero-value fields asserting no artifact verifies.
