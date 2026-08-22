# Q5456: attestation fetched from an attacker-influenced host - NewCmdVerify in verify.go

## Question
Can the attestation lookup performed by `NewCmdVerify` in [pkg/cmd/release/verify/verify.go](pkg/cmd/release/verify/verify.go#L40) be directed at a host the attacker controls (via repo coordinates, tenant, or flags visible in normal usage)?

## Target
- File/function: [pkg/cmd/release/verify/verify.go:40](pkg/cmd/release/verify/verify.go#L40) - `NewCmdVerify`
- Entrypoint: gh release verify
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Point the lookup at a server returning attacker-forged bundles.
- Invariant to test: Attestations are fetched only from the authenticated GitHub host and verified against trusted roots regardless of source.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test asserting the lookup host and that forged bundles still fail.
