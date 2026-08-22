# Q2610: policy fields default to permissive - DigestAlgForRef in fetch.go

## Question
Do unset or unparsed policy fields in `DigestAlgForRef` in [pkg/cmd/release/shared/fetch.go](pkg/cmd/release/shared/fetch.go#L182) default to matching everything (empty string, nil regex, zero value) rather than failing closed?

## Target
- File/function: [pkg/cmd/release/shared/fetch.go:182](pkg/cmd/release/shared/fetch.go#L182) - `DigestAlgForRef`
- Entrypoint: gh release
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Supply a bundle lacking the extension the policy checks.
- Invariant to test: Missing policy inputs fail closed.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Unit test constructing a policy with zero-value fields asserting no artifact verifies.
