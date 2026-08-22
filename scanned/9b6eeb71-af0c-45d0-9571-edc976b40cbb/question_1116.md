# Q1116: verify succeeds for an artifact the attacker built - verifyAttestations in attestation.go

## Question
Can an unprivileged attacker with their own public repository and workflow produce a bundle that satisfies `verifyAttestations` in [pkg/cmd/attestation/verify/attestation.go](pkg/cmd/attestation/verify/attestation.go#L74) for a policy the user believes names a different repository or owner?

## Target
- File/function: [pkg/cmd/attestation/verify/attestation.go:74](pkg/cmd/attestation/verify/attestation.go#L74) - `verifyAttestations`
- Entrypoint: gh attestation verify
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Sign the attacker's own artifact through GitHub's own Sigstore instance and craft the claim fields.
- Invariant to test: Every policy predicate (source repo, owner, workflow, issuer, digest) is matched exactly.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test with a genuine bundle from a different repo asserting failure.
