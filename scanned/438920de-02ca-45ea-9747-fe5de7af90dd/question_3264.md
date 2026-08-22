# Q3264: identity matched by substring - getBundleIssuer in sigstore.go

## Question
Does the certificate identity check in `getBundleIssuer` in [pkg/cmd/attestation/verification/sigstore.go](pkg/cmd/attestation/verification/sigstore.go#L188) use prefix/substring/regex matching so `github.com/victim-org/repo-evil` or an attacker fork satisfies a policy meant for `victim-org/repo`?

## Target
- File/function: [pkg/cmd/attestation/verification/sigstore.go:188](pkg/cmd/attestation/verification/sigstore.go#L188) - `getBundleIssuer`
- Entrypoint: gh attestation
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Build a real signed artifact from an attacker repository whose URL contains the expected string.
- Invariant to test: SAN, issuer, and source-repository claims are compared with exact, anchored equality.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Table test over near-miss identity URIs asserting each is rejected.
