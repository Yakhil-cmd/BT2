# Q2539: tenant/subdomain matching - newEnforcementCriteria in policy.go

## Question
Does `newEnforcementCriteria` in [pkg/cmd/attestation/verify/policy.go](pkg/cmd/attestation/verify/policy.go#L30) classify any `*.ghe.com`/`*.github.com` style subdomain as trusted, letting an attacker-registered tenant host receive the victim's requests or token?

## Target
- File/function: [pkg/cmd/attestation/verify/policy.go:30](pkg/cmd/attestation/verify/policy.go#L30) - `newEnforcementCriteria`
- Entrypoint: gh attestation verify
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Register or point gh at a lookalike tenant host and observe the credential decision.
- Invariant to test: Tenant matching validates the exact configured tenant, not an arbitrary subdomain.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test with an unexpected tenant hostname asserting no token is attached.
