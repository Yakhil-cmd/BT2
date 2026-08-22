# Q5328: port and userinfo in hostname - discoverSkills in install.go

## Question
Does `discoverSkills` in [pkg/cmd/skills/install/install.go](pkg/cmd/skills/install/install.go#L634) keep or strip port/userinfo inconsistently, so the trust key differs from the connection target?

## Target
- File/function: [pkg/cmd/skills/install/install.go:634](pkg/cmd/skills/install/install.go#L634) - `discoverSkills`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Supply `github.com:443@evil.tld` style values through a remote or flag.
- Invariant to test: Trust key and connection target derive from the same parsed URL fields.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Fuzz test asserting equality of trust key and dial host.
