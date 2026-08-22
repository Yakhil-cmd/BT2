# Q5393: host taken from repo remote - newEnforcementCriteria in policy.go

## Question
Does `newEnforcementCriteria` in [pkg/cmd/attestation/verify/policy.go](pkg/cmd/attestation/verify/policy.go#L30) accept the host embedded in a git remote URL of the repo the victim is standing in, without checking it against the authenticated hosts?

## Target
- File/function: [pkg/cmd/attestation/verify/policy.go:30](pkg/cmd/attestation/verify/policy.go#L30) - `newEnforcementCriteria`
- Entrypoint: gh attestation verify
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Publish a repo whose `.git/config` remote (or submodule) points at an attacker host, then have the victim run gh attestation verify inside a clone.
- Invariant to test: Hosts from repository metadata are only used after matching an authenticated host.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test in a temp repo with a hostile remote asserting gh refuses or does not authenticate.
