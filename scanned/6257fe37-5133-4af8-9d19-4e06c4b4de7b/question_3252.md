# Q3252: verify succeeds for an artifact the attacker built - extractAttestationDetail in verify.go

## Question
Can an unprivileged attacker with their own public repository and workflow produce a bundle that satisfies `extractAttestationDetail` in [pkg/cmd/attestation/verify/verify.go](pkg/cmd/attestation/verify/verify.go#L351) for a policy the user believes names a different repository or owner?

## Target
- File/function: [pkg/cmd/attestation/verify/verify.go:351](pkg/cmd/attestation/verify/verify.go#L351) - `extractAttestationDetail`
- Entrypoint: gh attestation verify
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Sign the attacker's own artifact through GitHub's own Sigstore instance and craft the claim fields.
- Invariant to test: Every policy predicate (source repo, owner, workflow, issuer, digest) is matched exactly.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test with a genuine bundle from a different repo asserting failure.
