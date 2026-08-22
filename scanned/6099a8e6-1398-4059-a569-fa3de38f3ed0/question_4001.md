# Q4001: identity matched by substring - (LiveClient).GetByDigest in client.go

## Question
Does the certificate identity check in `GetByDigest` in [pkg/cmd/attestation/api/client.go](pkg/cmd/attestation/api/client.go#L89) use prefix/substring/regex matching so `github.com/victim-org/repo-evil` or an attacker fork satisfies a policy meant for `victim-org/repo`?

## Target
- File/function: [pkg/cmd/attestation/api/client.go:89](pkg/cmd/attestation/api/client.go#L89) - `(LiveClient).GetByDigest`
- Entrypoint: gh attestation
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Build a real signed artifact from an attacker repository whose URL contains the expected string.
- Invariant to test: SAN, issuer, and source-repository claims are compared with exact, anchored equality.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Table test over near-miss identity URIs asserting each is rejected.
