# Q0034: suffix-match host confusion - getUsername in multi_account.go

## Question
Does the host comparison used by `getUsername` in [internal/config/migration/multi_account.go](internal/config/migration/multi_account.go#L162) use a suffix/contains check that accepts `evil-github.com` or `github.com.attacker.tld` as a trusted host?

## Target
- File/function: [internal/config/migration/multi_account.go:162](internal/config/migration/multi_account.go#L162) - `getUsername`
- Entrypoint: gh auth login
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Publish a remote or pass a URL whose hostname merely ends with or contains a trusted domain.
- Invariant to test: Host trust uses exact equality or a label-boundary check against the configured hosts.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Table test over lookalike hostnames asserting each is untrusted.
