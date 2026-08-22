# Q5784: host taken from URL userinfo - findEndCursor in pagination.go

## Question
Does the host check around `findEndCursor` in [pkg/cmd/api/pagination.go](pkg/cmd/api/pagination.go#L26) read the hostname from a string that can carry userinfo (`https://github.com@evil.tld/`), so validation and the actual connection disagree?

## Target
- File/function: [pkg/cmd/api/pagination.go:26](pkg/cmd/api/pagination.go#L26) - `findEndCursor`
- Entrypoint: gh api pagination
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Publish a remote/asset URL with an embedded `@` so gh validates `github.com` but connects to `evil.tld`.
- Invariant to test: The host used for the trust decision is `u.Hostname()` of the exact URL that will be dialed.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Fuzz URL strings with userinfo, `\`, and `#` and assert validation and dial host are identical.
