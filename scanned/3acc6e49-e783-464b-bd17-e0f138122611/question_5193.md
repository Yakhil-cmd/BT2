# Q5193: host taken from URL userinfo - ParseURL in finder.go

## Question
Does the host check around `ParseURL` in [pkg/cmd/pr/shared/finder.go](pkg/cmd/pr/shared/finder.go#L306) read the hostname from a string that can carry userinfo (`https://github.com@evil.tld/`), so validation and the actual connection disagree?

## Target
- File/function: [pkg/cmd/pr/shared/finder.go:306](pkg/cmd/pr/shared/finder.go#L306) - `ParseURL`
- Entrypoint: gh pr
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish a remote/asset URL with an embedded `@` so gh validates `github.com` but connects to `evil.tld`.
- Invariant to test: The host used for the trust decision is `u.Hostname()` of the exact URL that will be dialed.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Fuzz URL strings with userinfo, `\`, and `#` and assert validation and dial host are identical.
