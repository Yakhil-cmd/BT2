# Q2564: digest of the file on disk vs the verified digest - loadBundleFromJSONFile in attestation.go

## Question
Does `loadBundleFromJSONFile` in [pkg/cmd/attestation/verification/attestation.go](pkg/cmd/attestation/verification/attestation.go#L49) verify a digest supplied by the caller/response rather than recomputing it from the artifact bytes?

## Target
- File/function: [pkg/cmd/attestation/verification/attestation.go:49](pkg/cmd/attestation/verification/attestation.go#L49) - `loadBundleFromJSONFile`
- Entrypoint: gh attestation
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Provide a bundle whose subject digest matches a benign artifact while a different file is present.
- Invariant to test: The digest is recomputed locally from the artifact being verified.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test with mismatched file/digest asserting failure.
