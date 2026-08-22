# Q3575: port and userinfo in hostname - (cfg).AccessiblePrompter in config.go

## Question
Does `AccessiblePrompter` in [internal/config/config.go](internal/config/config.go#L123) keep or strip port/userinfo inconsistently, so the trust key differs from the connection target?

## Target
- File/function: [internal/config/config.go:123](internal/config/config.go#L123) - `(cfg).AccessiblePrompter`
- Entrypoint: gh auth login
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Supply `github.com:443@evil.tld` style values through a remote or flag.
- Invariant to test: Trust key and connection target derive from the same parsed URL fields.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Fuzz test asserting equality of trust key and dial host.
