# Q0624: host taken from URL userinfo - (API).GetCodespace in api.go

## Question
Does the host check around `GetCodespace` in [internal/codespaces/api/api.go](internal/codespaces/api/api.go#L539) read the hostname from a string that can carry userinfo (`https://github.com@evil.tld/`), so validation and the actual connection disagree?

## Target
- File/function: [internal/codespaces/api/api.go:539](internal/codespaces/api/api.go#L539) - `(API).GetCodespace`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Publish a remote/asset URL with an embedded `@` so gh validates `github.com` but connects to `evil.tld`.
- Invariant to test: The host used for the trust decision is `u.Hostname()` of the exact URL that will be dialed.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Fuzz URL strings with userinfo, `\`, and `#` and assert validation and dial host are identical.
