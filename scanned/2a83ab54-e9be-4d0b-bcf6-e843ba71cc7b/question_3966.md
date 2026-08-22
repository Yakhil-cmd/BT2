# Q3966: digest of the file on disk vs the verified digest - extractAttestationDetail in verify.go

## Question
Does `extractAttestationDetail` in [pkg/cmd/attestation/verify/verify.go](pkg/cmd/attestation/verify/verify.go#L351) verify a digest supplied by the caller/response rather than recomputing it from the artifact bytes?

## Target
- File/function: [pkg/cmd/attestation/verify/verify.go:351](pkg/cmd/attestation/verify/verify.go#L351) - `extractAttestationDetail`
- Entrypoint: gh attestation verify
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Provide a bundle whose subject digest matches a benign artifact while a different file is present.
- Invariant to test: The digest is recomputed locally from the artifact being verified.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test with mismatched file/digest asserting failure.
