# Q3301: subject/predicate mismatch accepted - digestLocalFileArtifact in file.go

## Question
Can an attestation whose subject name or predicate type does not match the artifact still satisfy `digestLocalFileArtifact` in [pkg/cmd/attestation/artifact/file.go](pkg/cmd/attestation/artifact/file.go#L10)?

## Target
- File/function: [pkg/cmd/attestation/artifact/file.go:10](pkg/cmd/attestation/artifact/file.go#L10) - `digestLocalFileArtifact`
- Entrypoint: gh attestation
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Publish a bundle whose statement subject points at a different artifact and attach it to the attacker's binary.
- Invariant to test: Subject digest and predicate type must both be matched before success.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Unit test with a mismatched subject asserting verification fails.
