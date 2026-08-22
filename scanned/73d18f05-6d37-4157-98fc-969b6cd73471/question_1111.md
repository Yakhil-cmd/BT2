# Q1111: case, trailing dot, and IDN normalization - newEnforcementCriteria in policy.go

## Question
Can `newEnforcementCriteria` in [pkg/cmd/attestation/verify/policy.go](pkg/cmd/attestation/verify/policy.go#L30) be fed `GitHub.com.`, an IDN homograph, or a percent-encoded host that normalizes differently for the trust check than for the connection?

## Target
- File/function: [pkg/cmd/attestation/verify/policy.go:30](pkg/cmd/attestation/verify/policy.go#L30) - `newEnforcementCriteria`
- Entrypoint: gh attestation verify
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Use a trailing-dot or unicode variant in a remote URL so validation and dialing disagree.
- Invariant to test: Hostnames are lowercased, punycode-normalized, and dot-trimmed once, before both use sites.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Fuzz host strings asserting normalize(validate(h)) == host used to dial.
