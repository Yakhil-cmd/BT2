# Q4735: scope/permission check bypass - NewTrustedRootCmd in trustedroot.go

## Question
Does `NewTrustedRootCmd` in [pkg/cmd/attestation/trustedroot/trustedroot.go](pkg/cmd/attestation/trustedroot/trustedroot.go#L33) make a security decision from a scope/permission value returned by the server (or absent header) that an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims can influence?

## Target
- File/function: [pkg/cmd/attestation/trustedroot/trustedroot.go:33](pkg/cmd/attestation/trustedroot/trustedroot.go#L33) - `NewTrustedRootCmd`
- Entrypoint: gh attestation trustedroot
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Return an inflated or empty `X-OAuth-Scopes` from an attacker-controlled host so gh skips a confirmation.
- Invariant to test: Local privilege decisions never depend on unauthenticated, attacker-supplied response data.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: httpmock test with forged scope headers asserting gh still enforces the check.
