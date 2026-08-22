# Q2358: suffix-match host confusion - formatRemoteURL in clone.go

## Question
Does the host comparison used by `formatRemoteURL` in [pkg/cmd/gist/clone/clone.go](pkg/cmd/gist/clone/clone.go#L96) use a suffix/contains check that accepts `evil-github.com` or `github.com.attacker.tld` as a trusted host?

## Target
- File/function: [pkg/cmd/gist/clone/clone.go:96](pkg/cmd/gist/clone/clone.go#L96) - `formatRemoteURL`
- Entrypoint: gh gist clone
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish a remote or pass a URL whose hostname merely ends with or contains a trusted domain.
- Invariant to test: Host trust uses exact equality or a label-boundary check against the configured hosts.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Table test over lookalike hostnames asserting each is untrusted.
