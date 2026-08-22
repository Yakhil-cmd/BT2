# Q2542: suffix-match host confusion - validateSignerWorkflow in policy.go

## Question
Does the host comparison used by `validateSignerWorkflow` in [pkg/cmd/attestation/verify/policy.go](pkg/cmd/attestation/verify/policy.go#L149) use a suffix/contains check that accepts `evil-github.com` or `github.com.attacker.tld` as a trusted host?

## Target
- File/function: [pkg/cmd/attestation/verify/policy.go:149](pkg/cmd/attestation/verify/policy.go#L149) - `validateSignerWorkflow`
- Entrypoint: gh attestation verify
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Publish a remote or pass a URL whose hostname merely ends with or contains a trusted domain.
- Invariant to test: Host trust uses exact equality or a label-boundary check against the configured hosts.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Table test over lookalike hostnames asserting each is untrusted.
