# Q0457: hostile JSON drives a security decision - getAttestationDetail in bundle.go

## Question
Does `getAttestationDetail` in [pkg/cmd/attestation/inspect/bundle.go](pkg/cmd/attestation/inspect/bundle.go#L77) unmarshal a response field that later gates a security decision (host, path, permission, verification result) without validating its shape or range?

## Target
- File/function: [pkg/cmd/attestation/inspect/bundle.go:77](pkg/cmd/attestation/inspect/bundle.go#L77) - `getAttestationDetail`
- Entrypoint: gh attestation inspect
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Return a crafted JSON body from an attacker-controlled host or an attacker-owned object.
- Invariant to test: Every response field used for a trust decision is validated against an allowlist before use.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Table test of hostile JSON payloads asserting rejection.
