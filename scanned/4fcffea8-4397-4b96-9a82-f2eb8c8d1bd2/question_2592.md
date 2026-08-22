# Q2592: JSON output shapes a downstream trust decision - (LiveClient).GetImageDigest in client.go

## Question
Can attacker-controlled fields in the JSON emitted through `GetImageDigest` in [pkg/cmd/attestation/artifact/oci/client.go](pkg/cmd/attestation/artifact/oci/client.go#L49) (certificate extensions, subject names) inject structure that misleads a script parsing it?

## Target
- File/function: [pkg/cmd/attestation/artifact/oci/client.go:49](pkg/cmd/attestation/artifact/oci/client.go#L49) - `(LiveClient).GetImageDigest`
- Entrypoint: gh attestation
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Put JSON-significant or control characters into fields the attacker owns.
- Invariant to test: Output is properly encoded and fields are validated before emission.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Golden test over hostile field values.
