# Q0445: limit/pagination hides the failing attestation - digestLocalFileArtifact in file.go

## Question
Does `digestLocalFileArtifact` in [pkg/cmd/attestation/artifact/file.go](pkg/cmd/attestation/artifact/file.go#L10) evaluate only the first N attestations returned, letting an attacker pad the list so the relevant check never runs?

## Target
- File/function: [pkg/cmd/attestation/artifact/file.go:10](pkg/cmd/attestation/artifact/file.go#L10) - `digestLocalFileArtifact`
- Entrypoint: gh attestation
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Publish many attestations so the meaningful one falls outside the window.
- Invariant to test: Verification is complete or explicitly reports truncation as a failure.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test with a padded list asserting failure or full evaluation.
