# Q5410: limit/pagination hides the failing attestation - newGitHubVerifier in sigstore.go

## Question
Does `newGitHubVerifier` in [pkg/cmd/attestation/verification/sigstore.go](pkg/cmd/attestation/verification/sigstore.go#L337) evaluate only the first N attestations returned, letting an attacker pad the list so the relevant check never runs?

## Target
- File/function: [pkg/cmd/attestation/verification/sigstore.go:337](pkg/cmd/attestation/verification/sigstore.go#L337) - `newGitHubVerifier`
- Entrypoint: gh attestation
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Publish many attestations so the meaningful one falls outside the window.
- Invariant to test: Verification is complete or explicitly reports truncation as a failure.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test with a padded list asserting failure or full evaluation.
