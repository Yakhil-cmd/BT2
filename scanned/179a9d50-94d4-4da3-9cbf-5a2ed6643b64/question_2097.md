# Q2097: host taken from URL userinfo - newCAPITransport in client.go

## Question
Does the host check around `newCAPITransport` in [pkg/cmd/agent-task/capi/client.go](pkg/cmd/agent-task/capi/client.go#L52) read the hostname from a string that can carry userinfo (`https://github.com@evil.tld/`), so validation and the actual connection disagree?

## Target
- File/function: [pkg/cmd/agent-task/capi/client.go:52](pkg/cmd/agent-task/capi/client.go#L52) - `newCAPITransport`
- Entrypoint: gh agent task
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Publish a remote/asset URL with an embedded `@` so gh validates `github.com` but connects to `evil.tld`.
- Invariant to test: The host used for the trust decision is `u.Hostname()` of the exact URL that will be dialed.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Fuzz URL strings with userinfo, `\`, and `#` and assert validation and dial host are identical.
