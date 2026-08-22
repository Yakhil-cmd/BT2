# Q5411: subject/predicate mismatch accepted - newGitHubVerifierWithTrustedRoot in sigstore.go

## Question
Can an attestation whose subject name or predicate type does not match the artifact still satisfy `newGitHubVerifierWithTrustedRoot` in [pkg/cmd/attestation/verification/sigstore.go](pkg/cmd/attestation/verification/sigstore.go#L362)?

## Target
- File/function: [pkg/cmd/attestation/verification/sigstore.go:362](pkg/cmd/attestation/verification/sigstore.go#L362) - `newGitHubVerifierWithTrustedRoot`
- Entrypoint: gh attestation
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Publish a bundle whose statement subject points at a different artifact and attach it to the attacker's binary.
- Invariant to test: Subject digest and predicate type must both be matched before success.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Unit test with a mismatched subject asserting verification fails.
