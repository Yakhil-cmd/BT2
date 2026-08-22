# Q5284: port and userinfo in hostname - ValidateSupportedHost in source.go

## Question
Does `ValidateSupportedHost` in [internal/skills/source/source.go](internal/skills/source/source.go#L56) keep or strip port/userinfo inconsistently, so the trust key differs from the connection target?

## Target
- File/function: [internal/skills/source/source.go:56](internal/skills/source/source.go#L56) - `ValidateSupportedHost`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Supply `github.com:443@evil.tld` style values through a remote or flag.
- Invariant to test: Trust key and connection target derive from the same parsed URL fields.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Fuzz test asserting equality of trust key and dial host.
