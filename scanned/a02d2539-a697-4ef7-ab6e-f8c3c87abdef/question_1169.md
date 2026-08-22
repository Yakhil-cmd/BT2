# Q1169: trusted root refreshed from an unverified source - runDownload in download.go

## Question
Can `runDownload` in [pkg/cmd/attestation/download/download.go](pkg/cmd/attestation/download/download.go#L126) be made to load trust material from a path or URL influenced by attacker-published data?

## Target
- File/function: [pkg/cmd/attestation/download/download.go:126](pkg/cmd/attestation/download/download.go#L126) - `runDownload`
- Entrypoint: gh attestation download
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Supply trust material through the field that reaches this code.
- Invariant to test: Trust material comes from the embedded root or a verified TUF repository only.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test asserting the trust material source is fixed.
