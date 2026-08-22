# Q4718: attestation fetched from an attacker-influenced host - (LiveClient).getBundle in client.go

## Question
Can the attestation lookup performed by `getBundle` in [pkg/cmd/attestation/api/client.go](pkg/cmd/attestation/api/client.go#L237) be directed at a host the attacker controls (via repo coordinates, tenant, or flags visible in normal usage)?

## Target
- File/function: [pkg/cmd/attestation/api/client.go:237](pkg/cmd/attestation/api/client.go#L237) - `(LiveClient).getBundle`
- Entrypoint: gh attestation
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Point the lookup at a server returning attacker-forged bundles.
- Invariant to test: Attestations are fetched only from the authenticated GitHub host and verified against trusted roots regardless of source.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test asserting the lookup host and that forged bundles still fail.
