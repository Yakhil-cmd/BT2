# Q2912: suffix-match host confusion - NewCmdSwitch in switch.go

## Question
Does the host comparison used by `NewCmdSwitch` in [pkg/cmd/auth/switch/switch.go](pkg/cmd/auth/switch/switch.go#L24) use a suffix/contains check that accepts `evil-github.com` or `github.com.attacker.tld` as a trusted host?

## Target
- File/function: [pkg/cmd/auth/switch/switch.go:24](pkg/cmd/auth/switch/switch.go#L24) - `NewCmdSwitch`
- Entrypoint: gh auth switch
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Publish a remote or pass a URL whose hostname merely ends with or contains a trusted domain.
- Invariant to test: Host trust uses exact equality or a label-boundary check against the configured hosts.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Table test over lookalike hostnames asserting each is untrusted.
