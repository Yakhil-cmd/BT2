# Q5452: attestation fetched from an attacker-influenced host - getOrgAndRepo in bundle.go

## Question
Can the attestation lookup performed by `getOrgAndRepo` in [pkg/cmd/attestation/inspect/bundle.go](pkg/cmd/attestation/inspect/bundle.go#L57) be directed at a host the attacker controls (via repo coordinates, tenant, or flags visible in normal usage)?

## Target
- File/function: [pkg/cmd/attestation/inspect/bundle.go:57](pkg/cmd/attestation/inspect/bundle.go#L57) - `getOrgAndRepo`
- Entrypoint: gh attestation inspect
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Point the lookup at a server returning attacker-forged bundles.
- Invariant to test: Attestations are fetched only from the authenticated GitHub host and verified against trusted roots regardless of source.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test asserting the lookup host and that forged bundles still fail.
