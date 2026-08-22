# Q1448: token for host A returned for host B - (AuthConfig).TokenFromKeyring in config.go

## Question
Does `TokenFromKeyring` in [internal/config/config.go](internal/config/config.go#L299) resolve the active token by falling back across hosts or accounts when the requested host has no entry?

## Target
- File/function: [internal/config/config.go:299](internal/config/config.go#L299) - `(AuthConfig).TokenFromKeyring`
- Entrypoint: gh auth login
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Point gh at an attacker host with no stored entry and see whether the github.com token is returned.
- Invariant to test: Token lookup is exact-match on host; a miss returns empty.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Table test asserting a miss returns no token and no fallback.
