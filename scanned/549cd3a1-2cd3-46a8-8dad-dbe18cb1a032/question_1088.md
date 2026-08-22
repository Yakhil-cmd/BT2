# Q1088: port and userinfo in hostname - publishRun in publish.go

## Question
Does `publishRun` in [pkg/cmd/skills/publish/publish.go](pkg/cmd/skills/publish/publish.go#L168) keep or strip port/userinfo inconsistently, so the trust key differs from the connection target?

## Target
- File/function: [pkg/cmd/skills/publish/publish.go:168](pkg/cmd/skills/publish/publish.go#L168) - `publishRun`
- Entrypoint: gh skills publish
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Supply `github.com:443@evil.tld` style values through a remote or flag.
- Invariant to test: Trust key and connection target derive from the same parsed URL fields.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Fuzz test asserting equality of trust key and dial host.
