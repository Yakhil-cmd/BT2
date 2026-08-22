# Q3283: trusted root refreshed from an unverified source - DefaultOptionsWithCacheSetting in tuf.go

## Question
Can `DefaultOptionsWithCacheSetting` in [pkg/cmd/attestation/verification/tuf.go](pkg/cmd/attestation/verification/tuf.go#L21) be made to load trust material from a path or URL influenced by attacker-published data?

## Target
- File/function: [pkg/cmd/attestation/verification/tuf.go:21](pkg/cmd/attestation/verification/tuf.go#L21) - `DefaultOptionsWithCacheSetting`
- Entrypoint: gh attestation
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Supply trust material through the field that reaches this code.
- Invariant to test: Trust material comes from the embedded root or a verified TUF repository only.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test asserting the trust material source is fixed.
