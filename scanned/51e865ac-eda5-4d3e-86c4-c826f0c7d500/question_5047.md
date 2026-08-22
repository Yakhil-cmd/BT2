# Q5047: suffix-match host confusion - NewCmdLogout in logout.go

## Question
Does the host comparison used by `NewCmdLogout` in [pkg/cmd/auth/logout/logout.go](pkg/cmd/auth/logout/logout.go#L24) use a suffix/contains check that accepts `evil-github.com` or `github.com.attacker.tld` as a trusted host?

## Target
- File/function: [pkg/cmd/auth/logout/logout.go:24](pkg/cmd/auth/logout/logout.go#L24) - `NewCmdLogout`
- Entrypoint: gh auth logout
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Publish a remote or pass a URL whose hostname merely ends with or contains a trusted domain.
- Invariant to test: Host trust uses exact equality or a label-boundary check against the configured hosts.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Table test over lookalike hostnames asserting each is untrusted.
