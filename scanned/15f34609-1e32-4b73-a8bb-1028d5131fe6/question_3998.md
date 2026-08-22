# Q3998: policy fields default to permissive - GitHubTUFOptions in tuf.go

## Question
Do unset or unparsed policy fields in `GitHubTUFOptions` in [pkg/cmd/attestation/verification/tuf.go](pkg/cmd/attestation/verification/tuf.go#L48) default to matching everything (empty string, nil regex, zero value) rather than failing closed?

## Target
- File/function: [pkg/cmd/attestation/verification/tuf.go:48](pkg/cmd/attestation/verification/tuf.go#L48) - `GitHubTUFOptions`
- Entrypoint: gh attestation
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Supply a bundle lacking the extension the policy checks.
- Invariant to test: Missing policy inputs fail closed.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Unit test constructing a policy with zero-value fields asserting no artifact verifies.
