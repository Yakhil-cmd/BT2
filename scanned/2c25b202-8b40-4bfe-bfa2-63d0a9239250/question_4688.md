# Q4688: tenant/subdomain matching - (Options).AreFlagsValid in options.go

## Question
Does `AreFlagsValid` in [pkg/cmd/attestation/verify/options.go](pkg/cmd/attestation/verify/options.go#L64) classify any `*.ghe.com`/`*.github.com` style subdomain as trusted, letting an attacker-registered tenant host receive the victim's requests or token?

## Target
- File/function: [pkg/cmd/attestation/verify/options.go:64](pkg/cmd/attestation/verify/options.go#L64) - `(Options).AreFlagsValid`
- Entrypoint: gh attestation verify
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Register or point gh at a lookalike tenant host and observe the credential decision.
- Invariant to test: Tenant matching validates the exact configured tenant, not an arbitrary subdomain.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test with an unexpected tenant hostname asserting no token is attached.
