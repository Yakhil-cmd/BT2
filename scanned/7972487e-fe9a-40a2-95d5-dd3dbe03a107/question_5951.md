# Q5951: host taken from URL userinfo - installRun in install.go

## Question
Does the host check around `installRun` in [pkg/cmd/skills/install/install.go](pkg/cmd/skills/install/install.go#L255) read the hostname from a string that can carry userinfo (`https://github.com@evil.tld/`), so validation and the actual connection disagree?

## Target
- File/function: [pkg/cmd/skills/install/install.go:255](pkg/cmd/skills/install/install.go#L255) - `installRun`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a remote/asset URL with an embedded `@` so gh validates `github.com` but connects to `evil.tld`.
- Invariant to test: The host used for the trust decision is `u.Hostname()` of the exact URL that will be dialed.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Fuzz URL strings with userinfo, `\`, and `#` and assert validation and dial host are identical.
