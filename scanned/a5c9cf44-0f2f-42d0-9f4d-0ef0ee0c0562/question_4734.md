# Q4734: JSON output shapes a downstream trust decision - (LiveClient).GetAttestations in client.go

## Question
Can attacker-controlled fields in the JSON emitted through `GetAttestations` in [pkg/cmd/attestation/artifact/oci/client.go](pkg/cmd/attestation/artifact/oci/client.go#L71) (certificate extensions, subject names) inject structure that misleads a script parsing it?

## Target
- File/function: [pkg/cmd/attestation/artifact/oci/client.go:71](pkg/cmd/attestation/artifact/oci/client.go#L71) - `(LiveClient).GetAttestations`
- Entrypoint: gh attestation
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Put JSON-significant or control characters into fields the attacker owns.
- Invariant to test: Output is properly encoded and fields are validated before emission.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Golden test over hostile field values.
