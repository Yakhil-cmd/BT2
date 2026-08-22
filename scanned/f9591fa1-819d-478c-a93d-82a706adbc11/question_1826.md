# Q1826: release verification trusts the release metadata - buildCertificateIdentityOption in policy.go

## Question
Does the release-asset verification path in `buildCertificateIdentityOption` in [pkg/cmd/attestation/verify/policy.go](pkg/cmd/attestation/verify/policy.go#L110) take the expected repository/owner from the release object (which an attacker owns for their own release) rather than from the user's expectation?

## Target
- File/function: [pkg/cmd/attestation/verify/policy.go:110](pkg/cmd/attestation/verify/policy.go#L110) - `buildCertificateIdentityOption`
- Entrypoint: gh attestation verify
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Publish a release in the attacker's repo and attest it there.
- Invariant to test: The expected identity is the user-specified repo, not the release's own.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test verifying an attacker release against a victim-repo expectation asserting failure.
