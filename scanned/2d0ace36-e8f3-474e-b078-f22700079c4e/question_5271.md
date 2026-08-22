# Q5271: suffix-match host confusion - authRecoveryCommand in cmd.go

## Question
Does the host comparison used by `authRecoveryCommand` in [internal/ghcmd/cmd.go](internal/ghcmd/cmd.go#L304) use a suffix/contains check that accepts `evil-github.com` or `github.com.attacker.tld` as a trusted host?

## Target
- File/function: [internal/ghcmd/cmd.go:304](internal/ghcmd/cmd.go#L304) - `authRecoveryCommand`
- Entrypoint: gh extension install
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish a remote or pass a URL whose hostname merely ends with or contains a trusted domain.
- Invariant to test: Host trust uses exact equality or a label-boundary check against the configured hosts.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Table test over lookalike hostnames asserting each is untrusted.
