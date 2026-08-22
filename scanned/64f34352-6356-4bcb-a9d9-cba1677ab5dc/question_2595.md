# Q2595: digest of the file on disk vs the verified digest - getTrustedRoot in trustedroot.go

## Question
Does `getTrustedRoot` in [pkg/cmd/attestation/trustedroot/trustedroot.go](pkg/cmd/attestation/trustedroot/trustedroot.go#L125) verify a digest supplied by the caller/response rather than recomputing it from the artifact bytes?

## Target
- File/function: [pkg/cmd/attestation/trustedroot/trustedroot.go:125](pkg/cmd/attestation/trustedroot/trustedroot.go#L125) - `getTrustedRoot`
- Entrypoint: gh attestation trustedroot
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Provide a bundle whose subject digest matches a benign artifact while a different file is present.
- Invariant to test: The digest is recomputed locally from the artifact being verified.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test with mismatched file/digest asserting failure.
