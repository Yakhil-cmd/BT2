# Q4641: suffix-match host confusion - scanAllAgents in update.go

## Question
Does the host comparison used by `scanAllAgents` in [pkg/cmd/skills/update/update.go](pkg/cmd/skills/update/update.go#L524) use a suffix/contains check that accepts `evil-github.com` or `github.com.attacker.tld` as a trusted host?

## Target
- File/function: [pkg/cmd/skills/update/update.go:524](pkg/cmd/skills/update/update.go#L524) - `scanAllAgents`
- Entrypoint: gh skills update
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a remote or pass a URL whose hostname merely ends with or contains a trusted domain.
- Invariant to test: Host trust uses exact equality or a label-boundary check against the configured hosts.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Table test over lookalike hostnames asserting each is untrusted.
