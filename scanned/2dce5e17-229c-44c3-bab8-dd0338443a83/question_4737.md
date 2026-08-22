# Q4737: JSON output shapes a downstream trust decision - NewDownloadCmd in download.go

## Question
Can attacker-controlled fields in the JSON emitted through `NewDownloadCmd` in [pkg/cmd/attestation/download/download.go](pkg/cmd/attestation/download/download.go#L19) (certificate extensions, subject names) inject structure that misleads a script parsing it?

## Target
- File/function: [pkg/cmd/attestation/download/download.go:19](pkg/cmd/attestation/download/download.go#L19) - `NewDownloadCmd`
- Entrypoint: gh attestation download
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Put JSON-significant or control characters into fields the attacker owns.
- Invariant to test: Output is properly encoded and fields are validated before emission.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Golden test over hostile field values.
