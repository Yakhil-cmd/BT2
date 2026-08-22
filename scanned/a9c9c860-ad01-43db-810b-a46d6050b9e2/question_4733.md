# Q4733: limit/pagination hides the failing attestation - (LiveClient).GetImageDigest in client.go

## Question
Does `GetImageDigest` in [pkg/cmd/attestation/artifact/oci/client.go](pkg/cmd/attestation/artifact/oci/client.go#L49) evaluate only the first N attestations returned, letting an attacker pad the list so the relevant check never runs?

## Target
- File/function: [pkg/cmd/attestation/artifact/oci/client.go:49](pkg/cmd/attestation/artifact/oci/client.go#L49) - `(LiveClient).GetImageDigest`
- Entrypoint: gh attestation
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Publish many attestations so the meaningful one falls outside the window.
- Invariant to test: Verification is complete or explicitly reports truncation as a failure.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test with a padded list asserting failure or full evaluation.
