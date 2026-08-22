# Q4682: digest bound to the wrong bytes - buildSigstoreVerifyPolicy in policy.go

## Question
Does `buildSigstoreVerifyPolicy` in [pkg/cmd/attestation/verify/policy.go](pkg/cmd/attestation/verify/policy.go#L134) compute or compare the artifact digest over data other than the exact bytes the user will run (for example a re-downloaded copy, a decompressed stream, or a manifest field)?

## Target
- File/function: [pkg/cmd/attestation/verify/policy.go:134](pkg/cmd/attestation/verify/policy.go#L134) - `buildSigstoreVerifyPolicy`
- Entrypoint: gh attestation verify
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Serve one artifact for verification and a different one for the actual download.
- Invariant to test: The verified digest is computed over the same bytes that are written to disk and returned to the caller.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test where the byte stream differs between verify and write, asserting a failure.
