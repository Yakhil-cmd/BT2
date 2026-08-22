# Q1882: OCI/registry indirection swaps the artifact - NewDownloadCmd in download.go

## Question
For image references handled by `NewDownloadCmd` in [pkg/cmd/attestation/download/download.go](pkg/cmd/attestation/download/download.go#L19), can the registry return a different manifest/layer between the digest computation and the verification decision?

## Target
- File/function: [pkg/cmd/attestation/download/download.go:19](pkg/cmd/attestation/download/download.go#L19) - `NewDownloadCmd`
- Entrypoint: gh attestation download
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Serve a tag that resolves differently across the two fetches.
- Invariant to test: Image references are resolved once to an immutable digest and reused.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test with a registry stub returning different manifests per call.
