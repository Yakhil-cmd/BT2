# Q5963: port and userinfo in hostname - buildInstallPlans in install.go

## Question
Does `buildInstallPlans` in [pkg/cmd/skills/install/install.go](pkg/cmd/skills/install/install.go#L993) keep or strip port/userinfo inconsistently, so the trust key differs from the connection target?

## Target
- File/function: [pkg/cmd/skills/install/install.go:993](pkg/cmd/skills/install/install.go#L993) - `buildInstallPlans`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Supply `github.com:443@evil.tld` style values through a remote or flag.
- Invariant to test: Trust key and connection target derive from the same parsed URL fields.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Fuzz test asserting equality of trust key and dial host.
